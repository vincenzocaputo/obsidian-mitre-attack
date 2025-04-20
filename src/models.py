
class MITREObject():
    """
    Define a generic MITRE Object
    """

    def __init__(self, name):
        self._name = name.replace('/', '／')
        self._references = dict()

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name.replace('/', '／')

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

class MITRETactic(MITREObject):
    """
    Define a tactic (x-mitre-tactic)
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)


class MITRETechnique(MITREObject):
    """
    Define a technique (attack-pattern)
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._kill_chain_phases = list()
        self._mitigations = list()
        self._groups = list()

    @property
    def internal_id(self):
        return self._internal_id

    @internal_id.setter
    def internal_id(self, internal_id):
        self._internal_id = internal_id

    @property
    def kill_chain_phases(self):
        return self._kill_chain_phases

    @kill_chain_phases.setter
    def kill_chain_phases(self, kill_chain_phase:dict):
        if 'kill_chain_name' not in kill_chain_phase or 'phase_name' not in kill_chain_phase:
            raise ValueError("The parameter provided is not supported")

        self._kill_chain_phases.append(kill_chain_phase)

    @property
    def is_subtechnique(self):
        return self._is_subtechnique

    @is_subtechnique.setter
    def is_subtechnique(self, is_subtechnique:bool):
        self._is_subtechnique = is_subtechnique

    @property
    def platforms(self):
        return self._platforms

    @platforms.setter
    def platforms(self, platforms):
        self._platforms = platforms

    @property
    def permissions_required(self):
        return self._permissions_required

    @permissions_required.setter
    def permissions_required(self, permissions_required):
        self._permissions_required = permissions_required

    @property
    def mitigations(self):
        return self._mitigations

    @mitigations.setter
    def mitigations(self, mitigation:dict):
        self._mitigations.append(mitigation)

    @property
    def groups(self):
        return self._groups

    @groups.setter
    def groups(self, group:dict):
        self.groups.append(group)


class MITREMitigation(MITREObject):
    """
    Define a mitigation (course-of-action)
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._mitigates = list()

    @property
    def is_deprecated(self):
        return self._is_deprecated

    @is_deprecated.setter
    def is_deprecated(self, is_deprecated):
        self._is_deprecated = is_deprecated

    @property
    def internal_id(self):
        return self._internal_id

    @internal_id.setter
    def internal_id(self, internal_id):
        self._internal_id = internal_id

    @property
    def mitigates(self):
        return self._mitigates

    @mitigates.setter
    def mitigates(self, mitigated_technique:dict):
        self._mitigates.append(mitigated_technique)


class MITREGroup(MITREObject):
    """
    Define a group
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._aliases = list()
        self._techniques_used = list()

    @property
    def internal_id(self):
        return self._internal_id

    @internal_id.setter
    def internal_id(self, internal_id):
        self._internal_id = internal_id

    @property
    def aliases(self):
        return self._aliases

    @aliases.setter
    def aliases(self, alias):
        self._aliases = alias

    @property
    def techniques_used(self):
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict):
        self._techniques_used.append(technique_used)

class MITRESoftware(MITREObject):
    """
    Define a Software
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._aliases = list()
        self._groups = list()

    @property
    def internal_id(self):
        return self._internal_id

    @internal_id.setter
    def internal_id(self, internal_id):
        self._internal_id = internal_id

    @property
    def aliases(self):
        return self._aliases

    @aliases.setter
    def aliases(self, alias):
        self._aliases = alias

    @property
    def groups(self):
        return self._groups

    @groups.setter
    def groups(self, group:dict):
        self._groups.append(group)
