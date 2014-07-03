import abc


class Attack(object):
    """
    Abstract base class for attacks.
    Attacks are required to implement the following methods:
       RunAttack - Initializes the attack
       EndAttack - Cleanly ends the attack

    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def run(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def end(self):
        raise NotImplementedError()