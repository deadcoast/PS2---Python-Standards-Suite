ps2/
├── __init__.py
├── config/
│   ├── __init__.py
│   ├── [X] default_settings.py
│   ├── [ ] linter_configs/
│   │   ├── [ ] __init__.py
│   │   ├── [ ] black.toml
│   │   ├── [ ] flake8.ini
│   │   ├── [ ] isort.cfg
│   │   ├── [ ] mypy.ini
│   │   ├── [ ] pylint.rc
│   │   └── [ ] pydocstyle.ini
│   ├── [ ] ci_templates/
│   │   ├── [ ] __init__.py
│   │   ├── [ ] github_actions.yml
│   │   ├── [ ] gitlab_ci.yml
│   │   └── [ ] jenkins.yml
│   └── [ ] security_configs/
│       ├── [ ] __init__.py
│       ├── [ ] bandit.yml
│       └── [ ] safety.yml
├── [ ]core/
│   ├── [ ] __init__.py
│   ├── [X] analyzer.py
│   ├── [X] code_quality.py
│   ├── [ ] conflict_resolver.py
│   ├── [X] dependency_manager.py
│   ├── [X] duplication_detector.py
│   ├── [ ] import_enforcer.py
│   ├── [ ] performance_monitor.py
│   ├── [X] project_generator.py
│   ├── [X] security_scanner.py
│   └── [X] task_manager.py
├── [ ] cli/
│   ├── [X] __init__.py
│   ├── [ ] commands/
│   │   ├── [ ] __init__.py
│   │   ├── [X] analyze.py
│   │   ├── [X] check.py
│   │   ├── [X] fix.py
│   │   ├── [X] generate.py
│   │   ├── [X] monitor.py
│   │   └── [ ] report.py
│   ├── [ ]helpers/
│   │   ├── [ ]__init__.py
│   │   ├── [ ] formatting.py
│   │   └── [ ] validation.py
│   └── [ ]main.py
├── [ ]git_hooks/
│   ├── [ ] __init__.py
│   ├── [ ] post_checkout
│   ├── [ ] pre_commit
│   └── [ ] pre_push
├── [ ]templates/
│   ├── [ ] __init__.py
│   ├── [ ] docs/
│   │   ├── [ ] __init__.py
│   │   ├── [ ] architecture.md
│   │   ├── [ ] changelog.md
│   │   └── [ ] readme.md
│   └── [ ] project/
│       ├── [ ] __init__.py
│       ├── [ ] gitignore_template
│       ├── [ ] pytest_ini
│       ├── [ ] setup_py
│       └── [ ] tox_ini
├── [ ]utils/
│   ├── [ ] __init__.py
│   ├── [ ] file_operations.py
│   ├── [ ] logging_utils.py
│   └── [ ] metrics.py
├── [ ]database/
│   ├── [ ] __init__.py
│   ├── [ ] metrics_db.py
│   └── [ ] schema.py
├── [ ]integrations/
│   ├── [ ] __init__.py
│   ├── [ ] issue_trackers/
│   │   ├── [ ] __init__.py
│   │   ├── [ ] github.py
│   │   └── [ ] jira.py
│   └── [ ] notifications/
│       ├── [ ] __init__.py
│       ├── [ ] email.py
│       └── [ ] slack.py
├── [X] ps2.py
├── [X] setup.py
└── [ ] requirements.txt