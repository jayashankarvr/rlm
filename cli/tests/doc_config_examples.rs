//! Every ```yaml block in the user docs must parse under strict config rules.

fn yaml_blocks(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in doc.lines() {
        match (&mut cur, line.trim_start()) {
            (None, l) if l.starts_with("```yaml") => cur = Some(String::new()),
            (Some(_), l) if l.starts_with("```") => out.push(cur.take().unwrap()),
            (Some(buf), _) => {
                buf.push_str(line);
                buf.push('\n');
            }
            _ => {}
        }
    }
    out
}

#[test]
fn every_documented_yaml_example_parses() {
    for (name, doc) in [
        ("README.md", include_str!("../../README.md")),
        ("CLAUDE.md", include_str!("../../CLAUDE.md")),
    ] {
        let blocks = yaml_blocks(doc);
        assert!(!blocks.is_empty(), "{name} has no yaml examples");
        for b in blocks {
            // Examples that start with a comment line like "# ~/.config/rlm/config.yaml" are still full files.
            let cfg: common::Config = serde_yaml_ng::from_str(&b)
                .unwrap_or_else(|e| panic!("{name} example does not parse: {e}\n{b}"));
            cfg.guard
                .validate()
                .unwrap_or_else(|e| panic!("{name} guard example invalid: {e}"));
        }
    }
}
