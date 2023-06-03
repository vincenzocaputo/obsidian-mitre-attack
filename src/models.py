
class Tactic():
    """
    Define a tactic (x-mitre-tactic)
    """

    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = description

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        self._id = id

    @property
    def mitre_url(self):
        return self._mitre_url

    @mitre_url.setter
    def mitre_url(self, mitre_url):
        self._mitre_url = mitre_url
