# Examples

* `sample-evidence.json`: eleven fictional evidence records (reserved example domains and addresses).
  It shows two websites repeating one claim, a third source disagreeing, similar usernames, similar
  company names, a DNS record that belongs to a domain, and one record with no source on purpose.

Try it:

1. `orkardch` → **4** Evidence Correlator → **1** Start a new investigation (any title)
2. **6** Import evidence from a JSON file → type the path to `sample-evidence.json`
3. **7** Find connections, confidence and contradictions
4. **8** Show the relationship graph
5. Back to the main menu → **6** Investigation Reports → choose a format

You should see: the "founding year" disagreement with both sides and their sources, the repeated claim
rated "plausible" (not "multiple independent sources") until you mark the sources independent, the
username and company-name matches labelled **fuzzy**, and the sourceless record rated **Unknown**.

Evidence file shape (only `type` and `value` are required):

```json
{ "findings": [
  { "type": "claim", "value": "Founded in 2010", "subject": "Acme Corp", "attribute": "founding year",
    "statementType": "claim",
    "source": { "url": "https://example.com/page", "publisher": "Example News", "retrievedAt": "2026-01-05T10:00:00Z" } }
] }
```
