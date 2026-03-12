# Conversion System Prompt Templates (G3)

Place override templates here as `<stack>_system.j2` to customise conversion behaviour without code changes.

Available stacks: pyspark, dbt, python

Template variables are defined in `org_config.yaml` under `conversion_prompts.<stack>.vars`.

If no template file exists for a stack, the built-in default prompt is used.

## Example

To override the PySpark conversion prompt:

1. Create `app/prompts/pyspark_system.j2` with your custom system prompt
2. Use Jinja2-style `{{variable}}` syntax for substitutions
3. Define variable values in `app/config/org_config.yaml`:

```yaml
conversion_prompts:
  pyspark:
    vars:
      company_name: "Acme Corp"
      data_quality_rules: "Check nulls and duplicates"
```

Then reference them in the template:

```
You are a {{company_name}} data engineer.
Follow these rules: {{data_quality_rules}}
```

Similarly for `dbt_system.j2` and `python_system.j2`.
