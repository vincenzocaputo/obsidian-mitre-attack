---
alias:
    {% for alias in aliases %}
    - {{alias}}
    {% endfor %}
mitre-attack: {{mitre_attack}}
tactic: 
    {% for tactic in tactics %}
    - {{tactic}}
    {% endfor %}
platforms:
    {% for plat in platforms %}
    - {{plat}}
    {% endfor %}
permissions required:
    {% if permissions_required %}
    {% for perm in permissions_required %}
    - {{perm}}
    {% endfor %}
    {% else %}
    - none
    {% endif %}
---

## {{title}}

{{description | parse_description(references)}}

{% if procedures %}
### Procedure Examples
| ID | Name | Use |
| --- | --- | --- |
{% for procedure in procedures %}| [[{{procedure['name']}}\|{{procedure['id']}}]] | {{procedure['name']}} | {{ procedure['description'] | parse_description(references) }} |
{% endfor %}
{% endif %}

{% if mitigations %}
### Mitigations
| ID | Name | Descrption |
| --- | --- | --- |
{% for mit in mitigations %}| [[{{mit['name']}}\|{{mit['id']}}]] | {{mit['name']}} | {{mit['description']}} |
{% endfor %}
{% endif %}

{% if subtechniques %}
### Sub-techniques
| ID | Name |
| --- | --- |
{% for sbt in subtechniques %}| [[{{sbt.name}}\|{{sbt.id}}]] | {{sbt.name}} |
{% endfor %}
{% endif %}

## References
{% for ref in references %}
[^{{ref['id']}}]: [{{ref['source_name']}}]({{ref['url']}})
{% endfor %}

