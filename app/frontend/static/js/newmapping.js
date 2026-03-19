// newmapping.js — Phase 3: New Mapping / greenfield authoring

let _patternsLoaded = false;
let _patternsData = [];

async function loadPatternsForTab() {
  if (_patternsLoaded) return;
  const sel = document.getElementById('newMappingPattern');
  try {
    const res = await fetch('/api/patterns');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    _patternsData = data.patterns || [];
    sel.innerHTML = '';
    _patternsData.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p.name;
      opt.textContent = p.name + ' — ' + p.description;
      sel.appendChild(opt);
    });
    sel.addEventListener('change', () => prefillYamlTemplate(_patternsData, sel.value));
    if (_patternsData.length > 0) prefillYamlTemplate(_patternsData, _patternsData[0].name);
    _patternsLoaded = true;
  } catch (e) {
    sel.innerHTML = '<option value="">Failed to load patterns — ' + e.message + '</option>';
  }
}

function prefillYamlTemplate(patterns, selectedName) {
  const p = patterns.find(x => x.name === selectedName);
  if (!p) return;
  const textarea = document.getElementById('newMappingYaml');
  textarea.value = buildYamlTemplate(selectedName, p.schema);
}

function buildYamlTemplate(patternName, schema) {
  const base = `pattern: ${patternName}\nmapping_name: m_example\nsource:\n  type: database\n  connection_string: oracle://user:pass@host/db\n  table: SOURCE_TABLE\ntarget:\n  type: database\n  connection_string: oracle://user:pass@host/dw\n  table: TARGET_TABLE\n`;
  const extras = {
    incremental_append: `watermark:\n  column: UPDATED_AT\n  data_type: datetime\n  initial: "1900-01-01 00:00:00"\n`,
    upsert:             `unique_key:\n  - ID\n`,
    scd2:               `scd2:\n  business_key:\n    - CUSTOMER_ID\n  tracked_cols:\n    - NAME\n    - EMAIL\n  effective_from: EFF_FROM\n  effective_to: EFF_TO\n  is_current: IS_CURRENT\n`,
    lookup_enrich:      `lookup:\n  table: REF_TABLE\n  join_key:\n    - ID\n  select_cols:\n    - DESCRIPTION\n`,
    aggregation_load:   `aggregation:\n  group_by:\n    - REGION\n  aggregates:\n    total_sales: "SUM(AMOUNT)"\n    cnt: "COUNT(*)"\n`,
    filter_and_route:   `routes:\n  - condition: "STATUS = 'ACTIVE'"\n    target:\n      type: database\n      connection_string: oracle://user:pass@host/dw\n      table: ACTIVE_TABLE\n`,
    union_consolidate:  `union_sources:\n  - type: database\n    connection_string: oracle://user:pass@host/db2\n    table: SOURCE_TABLE_2\n`,
    expression_transform: `column_map:\n  - target_col: FULL_NAME\n    expression: "FIRST_NAME || ' ' || LAST_NAME"\n`,
  };
  return base + (extras[patternName] || '');
}

async function generateXml() {
  const patternName = document.getElementById('newMappingPattern').value;
  const mappingName = document.getElementById('newMappingName').value.trim() || 'm_generated';
  const configYaml = document.getElementById('newMappingYaml').value;

  if (!patternName) { alert('Please select a pattern first.'); return; }

  const btn = document.getElementById('btnGenerateXml');
  btn.disabled = true;
  btn.textContent = 'Generating…';

  try {
    const res = await fetch(`/api/patterns/${encodeURIComponent(patternName)}/generate-xml`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({config_yaml: configYaml, mapping_name: mappingName}),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(JSON.stringify(data.detail || data));

    const outputEl = document.getElementById('newMappingOutput');
    outputEl.textContent = data.xml_content;
    outputEl.style.display = 'block';

    const blob = new Blob([data.xml_content], {type: 'application/xml'});
    const url = URL.createObjectURL(blob);
    const dl = document.getElementById('btnDownloadXml');
    dl.href = url;
    dl.download = mappingName + '.xml';
    dl.style.display = 'inline-block';
  } catch (e) {
    alert('Generation failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate Informatica XML';
  }
}
