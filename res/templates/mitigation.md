---
alias:
    {% for alias in aliases %}
    - {{alias}}
    {% endfor %}
mitre-attack: {{mitre_attack}}
---

## {{title}}

{{description | parse_description(references)}}

### Techniques Addressed by Mitigation
| ID | Name | Description |
| --- | --- | --- |
{% for technique in techniques %}| [[{{technique['name']}}\|{{technique['id']}}]] | {{technique['name']}} | {{ technique['description'] | parse_description(references) }} |
{% endfor %}

## References
{% for ref in references %}
[^{{ref['id']}}]: [{{ref['source_name']}}]({{ref['url']}})
{% endfor %}

