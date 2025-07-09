# Import built-in module to handle JSON files
import json

# Function to load and parse SARIF JSON file
def load_sarif_file(filepath):
    try:
        # Open the file with UTF-8 encoding to support all characters
        with open(filepath, 'r', encoding='utf-8') as file:
            # Parse JSON content into Python dictionary
            data = json.load(file)
            print("✅ Successfully loaded SARIF JSON file.")
            return data  # Return the parsed JSON object
    except Exception as e:
        # ❌ If any error occurs, raise a RuntimeError with explanation
        raise RuntimeError(f"❌ Error reading file: {e}")

# ✅ Main validation logic
def main():
    # Load and parse the SARIF file
    sarif_data = load_sarif_file("findings.json")

    # Access the list of findings under runs[0]
    results = sarif_data["runs"][0]["results"]

    # Assert that there are exactly 6 findings
    assert len(results) == 6, f"❌ Expected 6 findings, found {len(results)}"
    print("✅ Assertion Passed: Total number of findings is 6")

    # Filter findings with ruleId for SQL Injection
    sql_injection_findings = [
        r for r in results
        if r["ruleId"] == "php.lang.security.injection.tainted-sql-string.tainted-sql-string"
    ]

    # Assert exactly one SQL Injection finding exists
    assert len(sql_injection_findings) == 1, "❌ Expected exactly one SQL Injection finding"

    # Get that single SQL Injection finding
    sql_finding = sql_injection_findings[0]

    # Assert that the level of the finding is 'error'
    assert sql_finding["level"] == "error", "❌ SQL Injection level is not 'error'"
    print("✅ SQL Injection level is 'error'")

    # Check that security-severity > 8.0 (converted to float)
    assert float(sql_finding["properties"]["security-severity"]) > 8.0, \
        f"❌ SQL Injection severity is not > 8.0, got {sql_finding['properties']['security-severity']}"
    print("✅ SQL Injection security-severity is greater than 8.0")

    # Check that the issue owner is 'tmalbos'
    assert sql_finding["properties"]["issue_owner"] == "tmalbos", \
        "❌ SQL Injection issue_owner is not 'tmalbos'"
    print("✅ SQL Injection issue_owner is 'tmalbos'")

    # Extract the file name where the finding occurs
    file_name = sql_finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    # Ensure that the finding is in 'index.php'
    assert file_name == "index.php", \
        f"❌ SQL Injection is not in 'index.php', found in {file_name}"
    print("✅ SQL Injection is located in 'index.php'")

    # Filter findings related to package.json vulnerabilities
    package_findings = [
        r for r in results
        if r["ruleId"] == "json.npm.security.package-dependencies-check.package-dependencies-check"
    ]

    # Ensure there’s at least one finding related to package.json
    assert len(package_findings) >= 1, "❌ No findings found for package-dependencies-check"

    # For each such finding, ensure the issue_owner is 'Jose'
    for pf in package_findings:
        assert pf["properties"]["issue_owner"] == "Jose", \
            f"❌ package.json finding issue_owner is not 'Jose'"

    print("✅ All package.json findings have issue_owner 'Jose'")


if __name__ == "__main__":
    main()
