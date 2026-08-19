"""Tests for install.yaml scaffolding: the shape of the generated plan,
that it always validates through InstallPlan, and that the rendered YAML
round-trips back to an equivalent plan."""

import pytest
import yaml

from xcore_agent.scaffold import (
    ExtensionSpec,
    PluginSpec,
    ScaffoldOptions,
    render_install_plan_yaml,
    scaffold_install_plan,
)
from xcore_agent.schema.install import InstallPlan


def test_single_plugin_no_extras_produces_prepare_install_start():
    options = ScaffoldOptions(project_id="demo", plugins=[PluginSpec(id="demo")])

    plan_dict = scaffold_install_plan(options)

    ids = [s["id"] for s in plan_dict["steps"]]
    assert ids == ["prepare", "install_demo", "start", "healthcheck"]
    assert plan_dict["steps"][1]["snapshot"] is True
    assert plan_dict["steps"][2]["depends_on"] == ["install_demo"]


def test_without_healthcheck_omits_the_step():
    options = ScaffoldOptions(
        project_id="demo", plugins=[PluginSpec(id="demo")], with_healthcheck=False
    )

    plan_dict = scaffold_install_plan(options)

    assert "healthcheck" not in [s["id"] for s in plan_dict["steps"]]


def test_env_template_inserts_write_env_step_between_install_and_start():
    options = ScaffoldOptions(
        project_id="demo",
        plugins=[PluginSpec(id="demo", env_template="plugins/demo/.env.template")],
        with_healthcheck=False,
    )

    plan_dict = scaffold_install_plan(options)

    ids = [s["id"] for s in plan_dict["steps"]]
    assert ids == ["prepare", "install_demo", "write_env_demo", "start"]
    write_env_step = plan_dict["steps"][2]
    assert write_env_step["from"] == "plugins/demo/.env.template"
    assert write_env_step["depends_on"] == ["install_demo"]
    start_step = plan_dict["steps"][3]
    assert start_step["depends_on"] == ["write_env_demo"]


def test_multiple_plugins_each_get_their_own_install_step_and_start_depends_on_all():
    options = ScaffoldOptions(
        project_id="demo",
        plugins=[PluginSpec(id="alpha"), PluginSpec(id="beta")],
        with_healthcheck=False,
    )

    plan_dict = scaffold_install_plan(options)

    ids = [s["id"] for s in plan_dict["steps"]]
    assert ids == ["prepare", "install_alpha", "install_beta", "start"]
    start_step = plan_dict["steps"][-1]
    assert start_step["depends_on"] == ["install_alpha", "install_beta"]


def test_snapshot_false_omits_the_field():
    options = ScaffoldOptions(
        project_id="demo", plugins=[PluginSpec(id="demo", snapshot=False)], with_healthcheck=False
    )

    plan_dict = scaffold_install_plan(options)

    assert "snapshot" not in plan_dict["steps"][1]


def test_no_plugins_raises():
    options = ScaffoldOptions(project_id="demo", plugins=[])

    with pytest.raises(ValueError, match="at least one plugin"):
        scaffold_install_plan(options)


def test_scaffolded_plan_always_validates_through_install_plan():
    options = ScaffoldOptions(
        project_id="demo",
        plugins=[
            PluginSpec(id="alpha", env_template="plugins/alpha/.env.template"),
            PluginSpec(id="beta", snapshot=False),
        ],
    )

    plan_dict = scaffold_install_plan(options)

    plan = InstallPlan.model_validate(plan_dict)
    assert plan.execution_order()[0] == "prepare"
    assert plan.execution_order()[-1] == "healthcheck"


def test_extension_adds_install_extension_step_depended_on_by_start():
    options = ScaffoldOptions(
        project_id="demo",
        plugins=[PluginSpec(id="demo")],
        extensions=[ExtensionSpec(id="mail")],
    )

    plan_dict = scaffold_install_plan(options)

    ids = [s["id"] for s in plan_dict["steps"]]
    assert ids == ["prepare", "install_demo", "install_ext_mail", "start", "healthcheck"]
    ext_step = plan_dict["steps"][2]
    assert ext_step["action"] == "install_extension"
    assert ext_step["extension"] == "mail"
    assert ext_step["snapshot"] is True
    assert set(plan_dict["steps"][3]["depends_on"]) == {"install_demo", "install_ext_mail"}


def test_plugin_and_extension_may_share_an_id_without_step_id_collision():
    # install_<id> vs install_ext_<id> — see scaffold.py's comment on why.
    options = ScaffoldOptions(
        project_id="demo",
        plugins=[PluginSpec(id="xstorage")],
        extensions=[ExtensionSpec(id="xstorage")],
    )

    plan_dict = scaffold_install_plan(options)  # raises on duplicate step id if this regresses

    plan = InstallPlan.model_validate(plan_dict)
    assert "install_xstorage" in [s.id for s in plan.steps]
    assert "install_ext_xstorage" in [s.id for s in plan.steps]


def test_rendered_yaml_round_trips_to_an_equivalent_plan():
    options = ScaffoldOptions(
        project_id="demo", plugins=[PluginSpec(id="demo", env_template="plugins/demo/.env")]
    )
    plan_dict = scaffold_install_plan(options)

    rendered = render_install_plan_yaml(plan_dict)
    reparsed = InstallPlan.model_validate(yaml.safe_load(rendered))

    assert reparsed.project_id == "demo"
    assert reparsed.execution_order() == InstallPlan.model_validate(plan_dict).execution_order()
