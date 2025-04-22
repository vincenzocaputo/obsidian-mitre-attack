---
alias:
    {% for alias in aliases %}
    - {{alias}}
    {% endfor %}
mitre-attack: {{mitre_attack}}
---

## {{title}}

{{description | parse_description}}

