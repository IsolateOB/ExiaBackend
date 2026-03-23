pub const TEMPORARY_COPY_TEMPLATE_ID: &str = "__raid_copy__";
pub const LOCAL_DEFAULT_TEMPLATE_ID: &str = "default-local";
pub const LOCAL_TEMPLATE_ID_PREFIX: &str = "local-template-";
pub const LOCAL_ONLY_TEAM_TEMPLATE_ERROR: &str =
    "local-only team templates cannot be stored in cloud";

#[derive(Debug, PartialEq)]
pub struct CloudTemplateSelection<T> {
    pub templates: Vec<T>,
    pub skipped_count: usize,
    pub should_replace_existing: bool,
}

pub fn is_local_only_team_template_id(template_id: &str) -> bool {
    let trimmed = template_id.trim();
    trimmed == TEMPORARY_COPY_TEMPLATE_ID
        || trimmed == LOCAL_DEFAULT_TEMPLATE_ID
        || trimmed.starts_with(LOCAL_TEMPLATE_ID_PREFIX)
        || trimmed.contains("-conflict-")
}

pub fn validate_cloud_template_id(template_id: &str) -> std::result::Result<(), String> {
    if is_local_only_team_template_id(template_id) {
        return Err(format!(
            "{LOCAL_ONLY_TEAM_TEMPLATE_ERROR}: {}",
            template_id.trim()
        ));
    }
    Ok(())
}

pub fn select_templates_for_cloud_replace<T, F>(
    templates: Vec<T>,
    template_id: F,
) -> CloudTemplateSelection<T>
where
    F: Fn(&T) -> &str,
{
    let input_count = templates.len();
    let mut accepted = Vec::with_capacity(input_count);
    let mut skipped_count = 0;

    for template in templates {
        if is_local_only_team_template_id(template_id(&template)) {
            skipped_count += 1;
            continue;
        }
        accepted.push(template);
    }

    CloudTemplateSelection {
        should_replace_existing: true,
        templates: accepted,
        skipped_count,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_local_only_team_template_id, select_templates_for_cloud_replace,
        LOCAL_DEFAULT_TEMPLATE_ID, LOCAL_ONLY_TEAM_TEMPLATE_ERROR,
        LOCAL_TEMPLATE_ID_PREFIX, TEMPORARY_COPY_TEMPLATE_ID,
    };

    #[derive(Debug, PartialEq)]
    struct TestTemplate {
        id: String,
    }

    #[test]
    fn recognizes_local_only_team_template_ids() {
        assert!(is_local_only_team_template_id(TEMPORARY_COPY_TEMPLATE_ID));
        assert!(is_local_only_team_template_id(LOCAL_DEFAULT_TEMPLATE_ID));
        assert!(is_local_only_team_template_id(&format!(
            "{LOCAL_TEMPLATE_ID_PREFIX}1742091000"
        )));
        assert!(is_local_only_team_template_id(
            "raid-main-conflict-1742091000"
        ));
        assert!(!is_local_only_team_template_id("raid-main"));
    }

    #[test]
    fn splits_mixed_templates_for_cloud_replace() {
        let selection = select_templates_for_cloud_replace(
            vec![
                TestTemplate {
                    id: "raid-main".to_string(),
                },
                TestTemplate {
                    id: TEMPORARY_COPY_TEMPLATE_ID.to_string(),
                },
                TestTemplate {
                    id: LOCAL_DEFAULT_TEMPLATE_ID.to_string(),
                },
                TestTemplate {
                    id: format!("{LOCAL_TEMPLATE_ID_PREFIX}1742091000"),
                },
                TestTemplate {
                    id: "raid-main-conflict-1742091000".to_string(),
                },
            ],
            |template| template.id.as_str(),
        );

        assert_eq!(
            selection.templates,
            vec![TestTemplate {
                id: "raid-main".to_string(),
            }]
        );
        assert_eq!(selection.skipped_count, 4);
        assert!(selection.should_replace_existing);
    }

    #[test]
    fn local_only_only_payload_still_requests_cloud_replace() {
        let selection = select_templates_for_cloud_replace(
            vec![TestTemplate {
                id: TEMPORARY_COPY_TEMPLATE_ID.to_string(),
            }],
            |template| template.id.as_str(),
        );

        assert!(selection.templates.is_empty());
        assert_eq!(selection.skipped_count, 1);
        assert!(selection.should_replace_existing);
    }

    #[test]
    fn empty_payload_can_still_clear_cloud_templates() {
        let selection =
            select_templates_for_cloud_replace(Vec::<TestTemplate>::new(), |template| {
                template.id.as_str()
            });

        assert!(selection.templates.is_empty());
        assert_eq!(selection.skipped_count, 0);
        assert!(selection.should_replace_existing);
        assert_eq!(
            LOCAL_ONLY_TEAM_TEMPLATE_ERROR,
            "local-only team templates cannot be stored in cloud"
        );
    }
}
