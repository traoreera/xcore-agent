import pytest
from pydantic import ValidationError

from xcore_agent.schema.install import InstallPlan

VALID_PLAN = {
    "format_version": "1",
    "project_id": "prj_01JXYZ",
    "version": "1.0.0",
    "steps": [
        {"id": "prepare", "action": "prepare"},
        {
            "id": "database",
            "action": "provision",
            "plugin": "xcore.database",
            "snapshot": True,
        },
        {
            "id": "auth",
            "action": "install_plugin",
            "plugin": "xcore.auth",
            "snapshot": True,
            "depends_on": ["database"],
        },
        {"id": "configure", "action": "configure_plugin", "plugin": "xcore.auth"},
        {
            "id": "write_env",
            "action": "write_env",
            "plugin": "xcore.auth",
            "from": "plugins/auth/.env.template",
        },
        {"id": "start", "action": "start"},
        {"id": "healthcheck", "action": "healthcheck", "timeout": "30s", "retries": 3},
    ],
}


def test_valid_plan_parses():
    plan = InstallPlan.model_validate(VALID_PLAN)
    assert len(plan.steps) == 7


def test_execution_order_respects_dependencies():
    plan = InstallPlan.model_validate(VALID_PLAN)
    order = plan.execution_order()
    assert order.index("database") < order.index("auth")
    assert set(order) == {s.id for s in plan.steps}


def test_duration_string_is_parsed_to_seconds():
    plan = InstallPlan.model_validate(VALID_PLAN)
    hc = plan.step("healthcheck")
    assert hc.timeout_seconds == 30


def test_duplicate_step_id_is_rejected():
    bad = {**VALID_PLAN, "steps": [VALID_PLAN["steps"][0], VALID_PLAN["steps"][0]]}
    with pytest.raises(ValidationError, match="duplicate step id"):
        InstallPlan.model_validate(bad)


def test_unknown_dependency_is_rejected():
    bad = {
        **VALID_PLAN,
        "steps": [{"id": "a", "action": "prepare", "depends_on": ["missing"]}],
    }
    with pytest.raises(ValidationError, match="unknown step"):
        InstallPlan.model_validate(bad)


def test_self_dependency_is_rejected():
    bad = {
        **VALID_PLAN,
        "steps": [{"id": "a", "action": "prepare", "depends_on": ["a"]}],
    }
    with pytest.raises(ValidationError, match="cannot depend on itself"):
        InstallPlan.model_validate(bad)


def test_dependency_cycle_is_rejected():
    bad = {
        **VALID_PLAN,
        "steps": [
            {"id": "a", "action": "prepare", "depends_on": ["b"]},
            {"id": "b", "action": "prepare", "depends_on": ["a"]},
        ],
    }
    with pytest.raises(ValidationError, match="cycle"):
        InstallPlan.model_validate(bad)


def test_install_extension_step_parses():
    plan = InstallPlan.model_validate(
        {
            "format_version": "1",
            "project_id": "prj_01JXYZ",
            "version": "1.0.0",
            "steps": [
                {"id": "prepare", "action": "prepare"},
                {
                    "id": "mail",
                    "action": "install_extension",
                    "extension": "xmailler",
                    "snapshot": True,
                },
            ],
        }
    )
    step = plan.step("mail")
    assert step.action == "install_extension"
    assert step.extension == "xmailler"


def test_install_extension_step_rejects_invalid_extension_id():
    with pytest.raises(ValidationError, match="invalid extension id"):
        InstallPlan.model_validate(
            {
                "format_version": "1",
                "project_id": "prj_01JXYZ",
                "version": "1.0.0",
                "steps": [{"id": "mail", "action": "install_extension", "extension": "Not Valid"}],
            }
        )


def test_unknown_action_is_rejected():
    bad = {
        **VALID_PLAN,
        "steps": [{"id": "a", "action": "exec", "command": "rm -rf /"}],
    }
    with pytest.raises(ValidationError):
        InstallPlan.model_validate(bad)


def test_write_env_rejects_path_traversal():
    bad = {
        **VALID_PLAN,
        "steps": [{"id": "a", "action": "write_env", "plugin": "x", "from": "../../etc/passwd"}],
    }
    with pytest.raises(ValidationError, match="relative path"):
        InstallPlan.model_validate(bad)


def test_write_env_rejects_absolute_path():
    bad = {
        **VALID_PLAN,
        "steps": [{"id": "a", "action": "write_env", "plugin": "x", "from": "/etc/passwd"}],
    }
    with pytest.raises(ValidationError, match="relative path"):
        InstallPlan.model_validate(bad)


def test_extra_fields_are_rejected():
    bad = {**VALID_PLAN, "steps": [{"id": "a", "action": "prepare", "extra_field": "x"}]}
    with pytest.raises(ValidationError):
        InstallPlan.model_validate(bad)


def test_invalid_step_id_is_rejected():
    bad = {**VALID_PLAN, "steps": [{"id": "Not Valid!", "action": "prepare"}]}
    with pytest.raises(ValidationError):
        InstallPlan.model_validate(bad)


def test_notify_step_parses():
    plan = InstallPlan.model_validate(
        {
            "format_version": "1",
            "project_id": "prj_01JXYZ",
            "version": "1.0.0",
            "steps": [
                {
                    "id": "notify_ops",
                    "action": "notify",
                    "event": "deploy_success",
                    "message": "auth deployed",
                },
            ],
        }
    )
    step = plan.step("notify_ops")
    assert step.action == "notify"
    assert step.event == "deploy_success"
    assert step.message == "auth deployed"


def test_notify_step_message_is_optional():
    plan = InstallPlan.model_validate(
        {
            **VALID_PLAN,
            "steps": [{"id": "notify_ops", "action": "notify", "event": "deploy_success"}],
        }
    )
    assert plan.step("notify_ops").message is None


def test_notify_step_rejects_invalid_event():
    with pytest.raises(ValidationError, match="invalid notify event"):
        InstallPlan.model_validate(
            {
                **VALID_PLAN,
                "steps": [{"id": "notify_ops", "action": "notify", "event": "Not Valid!"}],
            }
        )
