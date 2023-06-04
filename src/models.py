
class Tactic():
    """
    Define a tactic (x-mitre-tactic)
    """

    def __init__(self, name):
        self._name = name
        self._references = dict()

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
    def references(self):
        return self._references

    @references.setter
    def references(self, reference:dict):
        if 'name' not in reference or 'url' not in reference:
            raise ValueError("The parameter provided is not supported")

        self._references[reference['name']] = reference['url']

