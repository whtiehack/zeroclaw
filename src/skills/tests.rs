use super::*;
use std::fs;
use std::sync::{Mutex, OnceLock};

fn open_skills_env_lock() -> &'static Mutex<()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvVarGuard {
    fn unset(key: &'static str) -> Self {
        let original = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key, original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[test]
fn load_empty_skills_dir() {
    let dir = tempfile::tempdir().unwrap();
    let skills = load_skills(dir.path());
    assert!(skills.is_empty());
}

#[test]
fn load_skill_from_toml() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("test-skill");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.toml"),
        r#"
[skill]
name = "test-skill"
description = "A test skill"
version = "1.0.0"
tags = ["test"]

[[tools]]
name = "hello"
description = "Says hello"
kind = "shell"
command = "echo hello"
"#,
    )
    .unwrap();

    let skills = load_skills(dir.path());
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "test-skill");
    assert_eq!(skills[0].tools.len(), 1);
    assert_eq!(skills[0].tools[0].name, "hello");
}

#[test]
fn load_skill_from_md() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("md-skill");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.md"),
        "# My Skill\nThis skill does cool things.\n",
    )
    .unwrap();

    let skills = load_skills(dir.path());
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "md-skill");
    assert!(skills[0].description.contains("cool things"));
}

#[test]
fn load_skill_from_md_frontmatter_uses_metadata_and_body() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("md-skill");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: pdf\ndescription: Use this skill for PDFs\nversion: 1.2.3\nauthor: maintainer\ntags:\n  - docs\n  - pdf\n---\n# PDF Processing Guide\nExtract text carefully.\n",
        )
        .unwrap();

    let skills = load_skills(dir.path());
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "pdf");
    assert_eq!(skills[0].description, "Use this skill for PDFs");
    assert_eq!(skills[0].version, "1.2.3");
    assert_eq!(skills[0].author.as_deref(), Some("maintainer"));
    assert_eq!(skills[0].tags, vec!["docs", "pdf"]);
    assert!(skills[0].prompts[0].contains("# PDF Processing Guide"));
    assert!(!skills[0].prompts[0].contains("name: pdf"));
}

#[test]
fn skills_to_prompt_empty() {
    let prompt = skills_to_prompt(&[], Path::new("/tmp"));
    assert!(prompt.is_empty());
}

#[test]
fn skills_to_prompt_with_skills() {
    let skills = vec![Skill {
        name: "test".to_string(),
        description: "A test".to_string(),
        version: "1.0.0".to_string(),
        author: None,
        tags: vec![],
        tools: vec![],
        prompts: vec!["Do the thing.".to_string()],
        location: None,
    }];
    let prompt = skills_to_prompt(&skills, Path::new("/tmp"));
    assert!(prompt.contains("<available_skills>"));
    assert!(prompt.contains("<name>test</name>"));
    assert!(prompt.contains("<instruction>Do the thing.</instruction>"));
}

#[test]
fn skills_to_prompt_compact_mode_omits_instructions_but_keeps_tools() {
    let skills = vec![Skill {
        name: "test".to_string(),
        description: "A test".to_string(),
        version: "1.0.0".to_string(),
        author: None,
        tags: vec![],
        tools: vec![SkillTool {
            name: "run".to_string(),
            description: "Run task".to_string(),
            kind: "shell".to_string(),
            command: "echo hi".to_string(),
            args: HashMap::new(),
        }],
        prompts: vec!["Do the thing.".to_string()],
        location: Some(PathBuf::from("/tmp/workspace/skills/test/SKILL.md")),
    }];
    let prompt = skills_to_prompt_with_mode(
        &skills,
        Path::new("/tmp/workspace"),
        crate::config::SkillsPromptInjectionMode::Compact,
    );

    assert!(prompt.contains("<available_skills>"));
    assert!(prompt.contains("<name>test</name>"));
    assert!(prompt.contains("<location>skills/test/SKILL.md</location>"));
    assert!(prompt.contains("loaded on demand"));
    assert!(prompt.contains("read_skill(name)"));
    assert!(!prompt.contains("<instructions>"));
    assert!(!prompt.contains("<instruction>Do the thing.</instruction>"));
    // Compact mode should still include tools so the LLM knows about them.
    // Registered tools (shell/script/http) appear under <callable_tools>.
    assert!(prompt.contains("<callable_tools"));
    assert!(prompt.contains("<name>test.run</name>"));
}

#[test]
fn init_skills_creates_readme() {
    let dir = tempfile::tempdir().unwrap();
    init_skills_dir(dir.path()).unwrap();
    assert!(dir.path().join("skills").join("README.md").exists());
}

#[test]
fn init_skills_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    init_skills_dir(dir.path()).unwrap();
    init_skills_dir(dir.path()).unwrap(); // second call should not fail
    assert!(dir.path().join("skills").join("README.md").exists());
}

#[test]
fn load_nonexistent_dir() {
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("nonexistent");
    let skills = load_skills(&fake);
    assert!(skills.is_empty());
}

#[test]
fn load_ignores_files_in_skills_dir() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    fs::create_dir_all(&skills_dir).unwrap();
    // A file, not a directory — should be ignored
    fs::write(skills_dir.join("not-a-skill.txt"), "hello").unwrap();
    let skills = load_skills(dir.path());
    assert!(skills.is_empty());
}

#[test]
fn load_ignores_dir_without_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let empty_skill = skills_dir.join("empty-skill");
    fs::create_dir_all(&empty_skill).unwrap();
    // Directory exists but no SKILL.toml or SKILL.md
    let skills = load_skills(dir.path());
    assert!(skills.is_empty());
}

#[test]
fn load_multiple_skills() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");

    for name in ["alpha", "beta", "gamma"] {
        let skill_dir = skills_dir.join(name);
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(
            skill_dir.join("SKILL.md"),
            format!("# {name}\nSkill {name} description.\n"),
        )
        .unwrap();
    }

    let skills = load_skills(dir.path());
    assert_eq!(skills.len(), 3);
}

#[test]
fn toml_skill_with_multiple_tools() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("multi-tool");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.toml"),
        r#"
[skill]
name = "multi-tool"
description = "Has many tools"
version = "2.0.0"
author = "tester"
tags = ["automation", "devops"]

[[tools]]
name = "build"
description = "Build the project"
kind = "shell"
command = "cargo build"

[[tools]]
name = "test"
description = "Run tests"
kind = "shell"
command = "cargo test"

[[tools]]
name = "deploy"
description = "Deploy via HTTP"
kind = "http"
command = "https://api.example.com/deploy"
"#,
    )
    .unwrap();

    let skills = load_skills(dir.path());
    assert_eq!(skills.len(), 1);
    let s = &skills[0];
    assert_eq!(s.name, "multi-tool");
    assert_eq!(s.version, "2.0.0");
    assert_eq!(s.author.as_deref(), Some("tester"));
    assert_eq!(s.tags, vec!["automation", "devops"]);
    assert_eq!(s.tools.len(), 3);
    assert_eq!(s.tools[0].name, "build");
    assert_eq!(s.tools[1].kind, "shell");
    assert_eq!(s.tools[2].kind, "http");
}

#[test]
fn toml_skill_minimal() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("minimal");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.toml"),
        r#"
[skill]
name = "minimal"
description = "Bare minimum"
"#,
    )
    .unwrap();

    let skills = load_skills(dir.path());
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].version, "0.1.0"); // default version
    assert!(skills[0].author.is_none());
    assert!(skills[0].tags.is_empty());
    assert!(skills[0].tools.is_empty());
}

#[test]
fn toml_skill_invalid_syntax_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("broken");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(skill_dir.join("SKILL.toml"), "this is not valid toml {{{{").unwrap();

    let skills = load_skills(dir.path());
    assert!(skills.is_empty()); // broken skill is skipped
}

#[test]
fn md_skill_heading_only() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("heading-only");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(skill_dir.join("SKILL.md"), "# Just a Heading\n").unwrap();

    let skills = load_skills(dir.path());
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].description, "No description");
}

#[test]
fn skills_to_prompt_includes_tools() {
    let skills = vec![Skill {
        name: "weather".to_string(),
        description: "Get weather".to_string(),
        version: "1.0.0".to_string(),
        author: None,
        tags: vec![],
        tools: vec![SkillTool {
            name: "get_weather".to_string(),
            description: "Fetch forecast".to_string(),
            kind: "shell".to_string(),
            command: "curl wttr.in".to_string(),
            args: HashMap::new(),
        }],
        prompts: vec![],
        location: None,
    }];
    let prompt = skills_to_prompt(&skills, Path::new("/tmp"));
    assert!(prompt.contains("weather"));
    // Registered tools (shell kind) now appear under <callable_tools> with
    // prefixed names (skill_name.tool_name).
    assert!(prompt.contains("<callable_tools"));
    assert!(prompt.contains("<name>weather.get_weather</name>"));
    assert!(prompt.contains("<description>Fetch forecast</description>"));
}

#[test]
fn skills_to_prompt_escapes_xml_content() {
    let skills = vec![Skill {
        name: "xml<skill>".to_string(),
        description: "A & B".to_string(),
        version: "1.0.0".to_string(),
        author: None,
        tags: vec![],
        tools: vec![],
        prompts: vec!["Use <tool> & check \"quotes\".".to_string()],
        location: None,
    }];

    let prompt = skills_to_prompt(&skills, Path::new("/tmp"));
    assert!(prompt.contains("<name>xml&lt;skill&gt;</name>"));
    assert!(prompt.contains("<description>A &amp; B</description>"));
    assert!(prompt
        .contains("<instruction>Use &lt;tool&gt; &amp; check &quot;quotes&quot;.</instruction>"));
}

#[test]
fn git_source_detection_accepts_remote_protocols_and_scp_style() {
    let sources = [
        "https://github.com/some-org/some-skill.git",
        "http://github.com/some-org/some-skill.git",
        "ssh://git@github.com/some-org/some-skill.git",
        "git://github.com/some-org/some-skill.git",
        "git@github.com:some-org/some-skill.git",
        "git@localhost:skills/some-skill.git",
    ];

    for source in sources {
        assert!(
            is_git_source(source),
            "expected git source detection for '{source}'"
        );
    }
}

#[test]
fn git_source_detection_rejects_local_paths_and_invalid_inputs() {
    let sources = [
        "./skills/local-skill",
        "/tmp/skills/local-skill",
        "C:\\skills\\local-skill",
        "git@github.com",
        "ssh://",
        "not-a-url",
        "dir/git@github.com:org/repo.git",
    ];

    for source in sources {
        assert!(
            !is_git_source(source),
            "expected local/invalid source detection for '{source}'"
        );
    }
}

#[test]
fn clawhub_source_is_not_git_source() {
    assert!(!is_git_source("https://clawhub.ai/steipete/summarize"));
    assert!(!is_git_source("https://www.clawhub.ai/steipete/summarize"));
    assert!(is_clawhub_source("https://clawhub.ai/steipete/summarize"));
    assert!(is_clawhub_source("clawhub:summarize"));
}

#[test]
fn clawhub_download_url_building() {
    assert_eq!(
        clawhub_download_url("https://clawhub.ai/steipete/gog").unwrap(),
        "https://clawhub.ai/api/v1/download?slug=steipete/gog"
    );
    assert_eq!(
        clawhub_download_url("https://www.clawhub.ai/steipete/gog").unwrap(),
        "https://clawhub.ai/api/v1/download?slug=steipete/gog"
    );
    assert_eq!(
        clawhub_download_url("https://clawhub.ai/gog").unwrap(),
        "https://clawhub.ai/api/v1/download?slug=gog"
    );
    assert_eq!(
        clawhub_download_url("clawhub:gog").unwrap(),
        "https://clawhub.ai/api/v1/download?slug=gog"
    );
}

#[test]
fn non_clawhub_https_urls_still_detected_as_git() {
    let git_urls = [
        "https://github.com/some-org/some-skill.git",
        "https://gitlab.com/owner/repo",
    ];
    for url in git_urls {
        assert!(!is_clawhub_source(url));
        assert!(is_git_source(url));
    }
}

#[test]
fn skills_dir_path() {
    let base = std::path::Path::new("/home/user/.zeroclaw");
    let dir = skills_dir(base);
    assert_eq!(dir, PathBuf::from("/home/user/.zeroclaw/skills"));
}

#[test]
fn toml_prefers_over_md() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("dual");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.toml"),
        "[skill]\nname = \"from-toml\"\ndescription = \"TOML wins\"\n",
    )
    .unwrap();
    fs::write(skill_dir.join("SKILL.md"), "# From MD\nMD description\n").unwrap();

    let skills = load_skills(dir.path());
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "from-toml"); // TOML takes priority
}

#[test]
fn open_skills_enabled_resolution_prefers_env_then_config_then_default_false() {
    assert!(!open_skills_enabled_from_sources(None, None));
    assert!(open_skills_enabled_from_sources(Some(true), None));
    assert!(!open_skills_enabled_from_sources(Some(true), Some("0")));
    assert!(open_skills_enabled_from_sources(Some(false), Some("yes")));
    // Invalid env values should fall back to config.
    assert!(open_skills_enabled_from_sources(
        Some(true),
        Some("invalid")
    ));
    assert!(!open_skills_enabled_from_sources(
        Some(false),
        Some("invalid")
    ));
}

#[test]
fn resolve_open_skills_dir_resolution_prefers_env_then_config_then_home() {
    let home = Path::new("/tmp/home-dir");
    assert_eq!(
        resolve_open_skills_dir_from_sources(
            Some("/tmp/env-skills"),
            Some("/tmp/config"),
            Some(home)
        ),
        Some(PathBuf::from("/tmp/env-skills"))
    );
    assert_eq!(
        resolve_open_skills_dir_from_sources(Some("   "), Some("/tmp/config-skills"), Some(home)),
        Some(PathBuf::from("/tmp/config-skills"))
    );
    assert_eq!(
        resolve_open_skills_dir_from_sources(None, None, Some(home)),
        Some(PathBuf::from("/tmp/home-dir/open-skills"))
    );
    assert_eq!(resolve_open_skills_dir_from_sources(None, None, None), None);
}

#[test]
fn load_skills_with_config_reads_open_skills_dir_without_network() {
    let _env_guard = open_skills_env_lock().lock().unwrap();
    let _enabled_guard = EnvVarGuard::unset("ZEROCLAW_OPEN_SKILLS_ENABLED");
    let _dir_guard = EnvVarGuard::unset("ZEROCLAW_OPEN_SKILLS_DIR");

    let dir = tempfile::tempdir().unwrap();
    let workspace_dir = dir.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("skills")).unwrap();

    let open_skills_dir = dir.path().join("open-skills-local");
    fs::create_dir_all(open_skills_dir.join("skills/http_request")).unwrap();
    fs::write(open_skills_dir.join("README.md"), "# open skills\n").unwrap();
    fs::write(
        open_skills_dir.join("CONTRIBUTING.md"),
        "# contribution guide\n",
    )
    .unwrap();
    fs::write(
        open_skills_dir.join("skills/http_request/SKILL.md"),
        "# HTTP request\nFetch API responses.\n",
    )
    .unwrap();

    let mut config = crate::config::Config::default();
    config.workspace_dir = workspace_dir.clone();
    config.skills.open_skills_enabled = true;
    config.skills.open_skills_dir = Some(open_skills_dir.to_string_lossy().to_string());

    let skills = load_skills_with_config(&workspace_dir, &config);
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "http_request");
    assert_ne!(skills[0].name, "CONTRIBUTING");
}

#[test]
fn load_open_skill_md_frontmatter_uses_metadata_and_strips_block() {
    let _env_guard = open_skills_env_lock().lock().unwrap();
    let _enabled_guard = EnvVarGuard::unset("ZEROCLAW_OPEN_SKILLS_ENABLED");
    let _dir_guard = EnvVarGuard::unset("ZEROCLAW_OPEN_SKILLS_DIR");

    let dir = tempfile::tempdir().unwrap();
    let workspace_dir = dir.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("skills")).unwrap();

    let open_skills_dir = dir.path().join("open-skills-local");
    fs::create_dir_all(open_skills_dir.join("skills/pdf")).unwrap();
    fs::write(
            open_skills_dir.join("skills/pdf/SKILL.md"),
            "---\nname: pdf\ndescription: Use this skill whenever the user needs PDF help.\nauthor: community\ntags:\n  - parser\n---\n# PDF Guide\nInspect files safely.\n",
        )
        .unwrap();

    let mut config = crate::config::Config::default();
    config.workspace_dir = workspace_dir.clone();
    config.skills.open_skills_enabled = true;
    config.skills.open_skills_dir = Some(open_skills_dir.to_string_lossy().to_string());

    let skills = load_skills_with_config(&workspace_dir, &config);
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "pdf");
    assert_eq!(
        skills[0].description,
        "Use this skill whenever the user needs PDF help."
    );
    assert_eq!(skills[0].author.as_deref(), Some("community"));
    assert!(skills[0].tags.iter().any(|tag| tag == "parser"));
    assert!(skills[0].tags.iter().any(|tag| tag == "open-skills"));
    assert!(skills[0].prompts[0].contains("# PDF Guide"));
    assert!(!skills[0].prompts[0].contains("description: Use this skill"));
}

#[test]
fn skill_with_scripts_skipped_when_allow_scripts_false() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("obsidian");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.toml"),
        r#"
[skill]
name = "obsidian"
description = "Obsidian vault tool"

[[tools]]
name = "search"
description = "Search vault"
kind = "shell"
command = "obsidian search {{query}}"
"#,
    )
    .unwrap();
    fs::write(skill_dir.join("setup.sh"), "#!/bin/bash\necho setup\n").unwrap();

    // With allow_scripts=false (default), skill should be skipped
    let skills = load_skills_from_directory(&skills_dir, false);
    assert!(
        skills.is_empty(),
        "skill with script files should be skipped when allow_scripts=false"
    );

    // With allow_scripts=true, skill should load
    let skills = load_skills_from_directory(&skills_dir, true);
    assert_eq!(skills.len(), 1, "skill should load when allow_scripts=true");
    assert_eq!(skills[0].name, "obsidian");
}
