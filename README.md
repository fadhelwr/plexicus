# SARIF API Response Validator

This script validates a SARIF-formatted API response (`findings.json`) from Plexicus' vulnerability scanner.

## How to Run

1. Ensure Python 3 is installed.
2. Save the script as `validate_sarif.py` and the JSON file as `findings.json` in the same directory.
3. Run the script:

```bash
python validate_sarif.py
```

## Validations Performed
1. Confirms exactly 6 findings exist.
2. For SQL Injection (ruleId: php.lang.security.injection.tainted-sql-string.tainted-sql-string):
   - level is "error"
   - `security-severity` is greater than 8.0
   - `issue_owner` is "tmalbos"
   - Located in "index.php"
3. For all **package.json-related** findings:
   - `issue_owner` is "Jose"

## Assumptions
#### 1. File Encoding is UTF-8
> It is assumed that the findings.json file uses UTF-8 encoding. Therefore, the script explicitly opens the file using `encoding='utf-8'` to prevent `UnicodeDecodeError`.

#### 2. SARIF Structure is Valid
> The JSON structure follows the SARIF 2.1.0 specification, especially with `runs[0]`.results containing the list of findings.

#### 3. Rule IDs are Unique
> When filtering specific findings (e.g., SQL Injection), it’s assumed that the ruleId is unique per finding type and that there is exactly one result for the targeted rule.

#### 4. Consistent Field Availability
> Fields such as `properties.security-severity`, `properties.issue_owner`, and `locations[0].physicalLocation.artifactLocation.uri` are assumed to always exist in each finding. The script does not handle missing fields.

#### 5. Case-Sensitive Rule Matching
> Rule IDs and file names are matched exactly as specified. For example, `ruleId == "php.lang.security.injection.tainted-sql-string.tainted-sql-string"` assumes precise casing and full ID match.

#### 6. Fixed Expected Output
> It is expected that:
  - There are exactly 6 findings.
  - SQL Injection exists with specific values.
  - All `package.json` findings are owned by "Jose".

#### 6. Script Run Locally
> The script is meant to be run in a local `python 3.x` environment, with no external dependencies beyond the standard library.
