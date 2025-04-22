---
alias:
    {% for alias in aliases %}- {{alias}}{% endfor %}
mitre-attack: {{mitre_attack}}
---

## {{title}}

{{description | parse_description(references)}}

### Techniques Used
| ID | Name | Description |
| --- | --- | --- |
{% for technique in techniques %}| [[{{technique['name']}}\|{{technique['id']}}]] | {{technique['name']}} | {{ technique['description'] | parse_description(references) }} |
{% endfor %}

{% if software %}
### Software
| ID | Name | Description |
| --- | --- | --- |
{% for sw in software %}| [[{{sw['name']}}\|{{sw['id']}}]] | {{sw['name']}} | sw['description'] | parse_description(references) }} |
{% endfor %}
{% endif %}

## References
{% for ref in references %}
[^{{ref['id']}}]: [{{ref['source_name']}}]({{ref['url']}})
{% endfor %}

