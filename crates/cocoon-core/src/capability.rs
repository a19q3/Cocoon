use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Capability {
    pub scheme: String,
    pub resource: String,
    pub access: AccessMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
    Execute,
    Connect,
    Any,
}

impl FromStr for Capability {
    type Err = crate::CocoonError;

    fn from_str(s: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(crate::CocoonError::CapabilityParse(format!(
                "invalid capability syntax: {}",
                s
            )));
        }
        let scheme = parts[0].to_string();
        let rest = parts[1];

        let (access, resource) = if let Some(pos) = rest.find('/') {
            let mode = &rest[..pos];
            let res = &rest[pos..];
            (parse_access(mode)?, res.to_string())
        } else {
            (AccessMode::Any, rest.to_string())
        };

        Ok(Capability {
            scheme,
            resource,
            access,
        })
    }
}

fn parse_access(s: &str) -> crate::Result<AccessMode> {
    match s {
        "readonly" => Ok(AccessMode::ReadOnly),
        "readwrite" => Ok(AccessMode::ReadWrite),
        "execute" => Ok(AccessMode::Execute),
        "connect" => Ok(AccessMode::Connect),
        "" => Ok(AccessMode::Any),
        _ => Err(crate::CocoonError::CapabilityParse(format!(
            "unknown access mode: {}",
            s
        ))),
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let access = match self.access {
            AccessMode::ReadOnly => "readonly",
            AccessMode::ReadWrite => "readwrite",
            AccessMode::Execute => "execute",
            AccessMode::Connect => "connect",
            AccessMode::Any => "",
        };
        if access.is_empty() {
            write!(f, "{}:{}", self.scheme, self.resource)
        } else {
            write!(f, "{}:{}{}", self.scheme, access, self.resource)
        }
    }
}

impl std::fmt::Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessMode::ReadOnly => write!(f, "readonly"),
            AccessMode::ReadWrite => write!(f, "readwrite"),
            AccessMode::Execute => write!(f, "execute"),
            AccessMode::Connect => write!(f, "connect"),
            AccessMode::Any => write!(f, "any"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capability() {
        let c: Capability = "file:/app/**".parse().unwrap();
        assert_eq!(c.scheme, "file");
        assert_eq!(c.resource, "/app/**");
        assert_eq!(c.access, AccessMode::Any);
    }

    #[test]
    fn parse_with_access() {
        let c: Capability = "log:/hello-service".parse().unwrap();
        assert_eq!(c.scheme, "log");
        assert_eq!(c.resource, "/hello-service");
        assert_eq!(c.access, AccessMode::Any);
    }

    #[test]
    fn display_roundtrip() {
        let c = Capability {
            scheme: "tcp".into(),
            resource: "/connect/*".into(),
            access: AccessMode::Connect,
        };
        let s = c.to_string();
        let c2: Capability = s.parse().unwrap();
        assert_eq!(c, c2);
    }
}
