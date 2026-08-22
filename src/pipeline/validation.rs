use crate::discovery::profile::BuildProfile;
use crate::reconstruction::model::DecodedMetadata;
use std::collections::HashMap;

pub struct ValidationIssue {
    pub message: String,
}

pub struct ValidationReport {
    pub errors: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn validate(metadata: &DecodedMetadata, profile: &BuildProfile) -> ValidationReport {
    let mut errors = Vec::new();
    if metadata.types.len() != profile.type_definition_count {
        errors.push(ValidationIssue {
            message: format!(
                "decoded {} types, expected {}",
                metadata.types.len(),
                profile.type_definition_count
            ),
        });
    }
    let image_type_count: usize = metadata
        .images
        .iter()
        .map(|image| image.type_count as usize)
        .sum();
    if image_type_count != metadata.types.len() {
        errors.push(ValidationIssue {
            message: format!(
                "image type ranges cover {image_type_count} types, decoded {}",
                metadata.types.len()
            ),
        });
    }
    if metadata.generics.gp_names.len() != metadata.generics.gp_containers.len() {
        errors.push(ValidationIssue {
            message: "generic parameter names and owners have different lengths".to_string(),
        });
    }
    if metadata.generics.gp_names.len() != profile.generic_parameter_count {
        errors.push(ValidationIssue {
            message: format!(
                "decoded {} generic parameters, expected {}",
                metadata.generics.gp_names.len(),
                profile.generic_parameter_count
            ),
        });
    }
    if metadata.generics.containers.len() != profile.generic_container_count {
        errors.push(ValidationIssue {
            message: format!(
                "decoded {} generic containers, expected {}",
                metadata.generics.containers.len(),
                profile.generic_container_count
            ),
        });
    }
    for (type_index, type_definition) in metadata.types.iter().enumerate() {
        let Ok(container_index) = usize::try_from(type_definition.generic_container_index) else {
            continue;
        };
        match metadata.generics.containers.get(container_index) {
            Some(&(owner, _, 0, _)) if owner == type_index as i32 => {}
            Some(&(owner, _, is_method, _)) => errors.push(ValidationIssue {
                message: format!(
                    "type {type_index} generic container {container_index} has owner {owner} and method flag {is_method}"
                ),
            }),
            None => errors.push(ValidationIssue {
                message: format!(
                    "type {type_index} references missing generic container {container_index}"
                ),
            }),
        }
    }
    for (method_index, method) in metadata.methods.iter().enumerate() {
        let Ok(container_index) = usize::try_from(method.generic_container_index) else {
            continue;
        };
        match metadata.generics.containers.get(container_index) {
            Some(&(owner, _, 1, _)) if owner == method_index as i32 => {}
            Some(&(owner, _, is_method, _)) => errors.push(ValidationIssue {
                message: format!(
                    "method {method_index} generic container {container_index} has owner {owner} and method flag {is_method}"
                ),
            }),
            None => errors.push(ValidationIssue {
                message: format!(
                    "method {method_index} references missing generic container {container_index}"
                ),
            }),
        }
    }
    let generic_parameter_count = metadata.generics.gp_names.len();
    for (name, count) in [
        (
            "constraint starts",
            metadata.generics.gp_constraint_starts.len(),
        ),
        (
            "constraint counts",
            metadata.generics.gp_constraint_counts.len(),
        ),
        ("ordinals", metadata.generics.gp_nums.len()),
        ("flags", metadata.generics.gp_flags.len()),
    ] {
        if count != generic_parameter_count {
            errors.push(ValidationIssue {
                message: format!(
                    "generic parameter {name} contain {count} entries, expected {generic_parameter_count}"
                ),
            });
        }
    }
    for (index, (&start, &count)) in metadata
        .generics
        .gp_constraint_starts
        .iter()
        .zip(&metadata.generics.gp_constraint_counts)
        .enumerate()
    {
        if start < 0 || count < 0 {
            errors.push(ValidationIssue {
                message: format!("generic parameter {index} has a negative constraint range"),
            });
            continue;
        }
        let end = start as usize + count as usize;
        if end > metadata.generics.constraints.len() {
            errors.push(ValidationIssue {
                message: format!("generic parameter {index} has an invalid constraint range"),
            });
        }
    }
    for (index, &constraint) in metadata.generics.constraints.iter().enumerate() {
        if constraint < 0 {
            errors.push(ValidationIssue {
                message: format!("generic constraint {index} has a negative type index"),
            });
        }
    }
    for (index, &container_index) in metadata.generics.gp_containers.iter().enumerate() {
        let Ok(container_index) = usize::try_from(container_index) else {
            errors.push(ValidationIssue {
                message: format!("generic parameter {index} has a negative container index"),
            });
            continue;
        };
        match metadata.generics.containers.get(container_index) {
            Some(&(_, parameter_count, _, parameter_start)) => {
                let end = parameter_start.saturating_add(parameter_count);
                if parameter_start < 0 || index < parameter_start as usize || index >= end as usize
                {
                    errors.push(ValidationIssue {
                        message: format!(
                            "generic parameter {index} is outside container {container_index} range"
                        ),
                    });
                }
            }
            None => errors.push(ValidationIssue {
                message: format!(
                    "generic parameter {index} references missing container {container_index}"
                ),
            }),
        }
    }
    if metadata.string_literals.len() != profile.string_literal_count {
        errors.push(ValidationIssue {
            message: format!(
                "decoded {} string literals, expected {}",
                metadata.string_literals.len(),
                profile.string_literal_count
            ),
        });
    }
    let declared_methods = metadata
        .types
        .iter()
        .filter(|value| value.m_count > 0)
        .map(|value| value.m_start as usize + value.m_count as usize)
        .max()
        .unwrap_or(0);
    if declared_methods != metadata.methods.len() {
        errors.push(ValidationIssue {
            message: format!(
                "type method ranges cover {declared_methods} definitions, decoded {}",
                metadata.methods.len()
            ),
        });
    }
    let declared_parameters = metadata
        .methods
        .iter()
        .filter(|value| value.parameter_start >= 0)
        .map(|value| value.parameter_start as usize + value.parameter_count as usize)
        .max()
        .unwrap_or(0);
    if declared_parameters != metadata.parameters.len() {
        errors.push(ValidationIssue {
            message: format!(
                "method parameter ranges cover {declared_parameters} definitions, decoded {}",
                metadata.parameters.len()
            ),
        });
    }
    let declared_properties: usize = metadata
        .types
        .iter()
        .map(|value| value.property_count as usize)
        .sum();
    if declared_properties != metadata.properties.len() {
        errors.push(ValidationIssue {
            message: format!(
                "type property ranges cover {declared_properties} definitions, decoded {}",
                metadata.properties.len()
            ),
        });
    }
    let declared_events: usize = metadata
        .types
        .iter()
        .map(|value| value.event_count as usize)
        .sum();
    if declared_events != metadata.events.len() {
        errors.push(ValidationIssue {
            message: format!(
                "type event ranges cover {declared_events} definitions, decoded {}",
                metadata.events.len()
            ),
        });
    }
    for (type_index, value) in metadata.types.iter().enumerate() {
        validate_member_range(
            &mut errors,
            "property",
            type_index,
            value.property_start,
            value.property_count,
            metadata.properties.len(),
        );
        validate_member_range(
            &mut errors,
            "event",
            type_index,
            value.event_start,
            value.event_count,
            metadata.events.len(),
        );
        validate_member_range(
            &mut errors,
            "interface",
            type_index,
            value.if_start,
            value.if_count,
            metadata.interfaces.len(),
        );
        validate_member_range(
            &mut errors,
            "vtable",
            type_index,
            value.vtable_start,
            value.vtable_count,
            metadata.vtable_methods.len(),
        );
        validate_member_range(
            &mut errors,
            "interface offset",
            type_index,
            value.interface_offset_start,
            value.interface_offset_count,
            metadata.interface_offsets.len(),
        );
        if value.property_count > 0 {
            let Some(properties) = usize::try_from(value.property_start)
                .ok()
                .and_then(|start| {
                    metadata
                        .properties
                        .get(start..start + value.property_count as usize)
                })
            else {
                continue;
            };
            for (local_index, property) in properties.iter().enumerate() {
                if property.name.is_empty() {
                    errors.push(ValidationIssue {
                        message: format!(
                            "property {local_index} on type {type_index} has an empty name"
                        ),
                    });
                }
                for (kind, accessor) in [("getter", property.get), ("setter", property.set)] {
                    if accessor < -1 || accessor >= value.m_count as i32 {
                        errors.push(ValidationIssue {
                            message: format!(
                                "property {local_index} on type {type_index} has an invalid {kind}"
                            ),
                        });
                    }
                }
            }
        }
        if value.event_count > 0 {
            let Some(events) = usize::try_from(value.event_start).ok().and_then(|start| {
                metadata
                    .events
                    .get(start..start + value.event_count as usize)
            }) else {
                continue;
            };
            for (local_index, event) in events.iter().enumerate() {
                if event.name.is_empty() {
                    errors.push(ValidationIssue {
                        message: format!(
                            "event {local_index} on type {type_index} has an empty name"
                        ),
                    });
                }
                if event.type_index < 0 {
                    errors.push(ValidationIssue {
                        message: format!(
                            "event {local_index} on type {type_index} has a negative type index"
                        ),
                    });
                }
                for (kind, accessor) in [
                    ("add method", event.add),
                    ("remove method", event.remove),
                    ("raise method", event.raise),
                ] {
                    if accessor < -1 || accessor >= value.m_count as i32 {
                        errors.push(ValidationIssue {
                            message: format!(
                                "event {local_index} on type {type_index} has an invalid {kind}"
                            ),
                        });
                    }
                }
            }
        }
    }
    for (index, &type_index) in metadata.interfaces.iter().enumerate() {
        if type_index < 0 {
            errors.push(ValidationIssue {
                message: format!("interface entry {index} has a negative type index"),
            });
        }
    }
    for (index, value) in metadata.interface_offsets.iter().enumerate() {
        if value.type_index < 0 {
            errors.push(ValidationIssue {
                message: format!("interface offset {index} has a negative type index"),
            });
        }
        if value.offset < 0 {
            errors.push(ValidationIssue {
                message: format!("interface offset {index} has a negative slot offset"),
            });
        }
    }
    for (index, &encoded_method) in metadata.vtable_methods.iter().enumerate() {
        let usage = encoded_method >> 29;
        let method_index = (encoded_method & 0x1FFF_FFFF) as usize;
        if !matches!(usage, 0 | 3 | 6) {
            errors.push(ValidationIssue {
                message: format!("vtable entry {index} has unsupported usage kind {usage}"),
            });
        } else if usage != 6 && method_index >= metadata.methods.len() {
            errors.push(ValidationIssue {
                message: format!("vtable entry {index} has an invalid method index"),
            });
        }
    }
    for (index, value) in metadata.field_defaults.iter().enumerate() {
        if value.field_index < 0 || value.field_index as usize >= metadata.fields.len() {
            errors.push(ValidationIssue {
                message: format!("field default {index} has an invalid field index"),
            });
        }
        if value.type_index < 0 {
            errors.push(ValidationIssue {
                message: format!("field default {index} has a negative type index"),
            });
        }
        if value.data_index < 0 || value.data_index as usize >= metadata.default_value_data.len() {
            errors.push(ValidationIssue {
                message: format!("field default {index} has an invalid data index"),
            });
        }
    }
    if metadata.field_defaults.len() != metadata.expected_field_default_count {
        errors.push(ValidationIssue {
            message: format!(
                "decoded {} field defaults, expected {}",
                metadata.field_defaults.len(),
                metadata.expected_field_default_count
            ),
        });
    }
    for (index, value) in metadata.parameter_defaults.iter().enumerate() {
        if value.parameter_index < 0 || value.parameter_index as usize >= metadata.parameters.len()
        {
            errors.push(ValidationIssue {
                message: format!("parameter default {index} has an invalid parameter index"),
            });
        }
        if value.type_index < 0 {
            errors.push(ValidationIssue {
                message: format!("parameter default {index} has a negative type index"),
            });
        }
        if value.data_index < -1
            || value.data_index >= 0
                && value.data_index as usize >= metadata.default_value_data.len()
        {
            errors.push(ValidationIssue {
                message: format!("parameter default {index} has an invalid data index"),
            });
        }
    }
    if metadata.parameter_defaults.len() != metadata.expected_parameter_default_count {
        errors.push(ValidationIssue {
            message: format!(
                "decoded {} parameter defaults, expected {}",
                metadata.parameter_defaults.len(),
                metadata.expected_parameter_default_count
            ),
        });
    }
    let declared_nested: usize = metadata
        .types
        .iter()
        .map(|value| value.nested_count as usize)
        .sum();
    if declared_nested != metadata.nested_types.len() {
        errors.push(ValidationIssue {
            message: format!(
                "nested type ranges cover {declared_nested} entries, emitted {}",
                metadata.nested_types.len()
            ),
        });
    }
    let byval_to_definition = metadata
        .types
        .iter()
        .enumerate()
        .map(|(index, value)| (value.byval_type_index, index))
        .collect::<HashMap<_, _>>();
    let mut nested_seen = vec![false; metadata.types.len()];
    for (parent, value) in metadata.types.iter().enumerate() {
        if value.nested_count == 0 {
            continue;
        }
        let Ok(start) = usize::try_from(value.nested_start) else {
            errors.push(ValidationIssue {
                message: format!("type {parent} has a negative nested type start"),
            });
            continue;
        };
        let Some(children) = metadata
            .nested_types
            .get(start..start + value.nested_count as usize)
        else {
            errors.push(ValidationIssue {
                message: format!("type {parent} has an invalid nested type range"),
            });
            continue;
        };
        for &child in children {
            let Ok(child) = usize::try_from(child) else {
                errors.push(ValidationIssue {
                    message: format!("type {parent} has a negative nested child index"),
                });
                continue;
            };
            let Some(child_type) = metadata.types.get(child) else {
                errors.push(ValidationIssue {
                    message: format!("type {parent} has an out-of-range nested child {child}"),
                });
                continue;
            };
            if byval_to_definition.get(&child_type.declaring_type_index) != Some(&parent) {
                errors.push(ValidationIssue {
                    message: format!("nested child {child} does not declare type {parent}"),
                });
            }
            if std::mem::replace(&mut nested_seen[child], true) {
                errors.push(ValidationIssue {
                    message: format!("nested child {child} is emitted more than once"),
                });
            }
        }
    }
    for (index, value) in metadata.types.iter().enumerate() {
        if value.declaring_type_index >= 0 && !nested_seen[index] {
            errors.push(ValidationIssue {
                message: format!("nested type {index} is absent from its declaring type range"),
            });
        }
    }
    ValidationReport { errors }
}

fn validate_member_range(
    errors: &mut Vec<ValidationIssue>,
    kind: &str,
    type_index: usize,
    start: i32,
    count: u16,
    total: usize,
) {
    if count == 0 {
        if start != -1 {
            errors.push(ValidationIssue {
                message: format!("type {type_index} has a nonempty {kind} start with zero count"),
            });
        }
        return;
    }
    let Ok(start) = usize::try_from(start) else {
        errors.push(ValidationIssue {
            message: format!("type {type_index} has a negative {kind} start"),
        });
        return;
    };
    if start
        .checked_add(count as usize)
        .is_none_or(|end| end > total)
    {
        errors.push(ValidationIssue {
            message: format!("type {type_index} has an invalid {kind} range"),
        });
    }
}
