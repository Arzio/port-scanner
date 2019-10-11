from enum import Enum


class ConnectionMethod(Enum):
    """
    Enum (classe com constantes que, por debaixo dos panos, são enumeradas) que representa
    os tipos de protocolos/métodos para fazer scan em portas
    """
    TCP = 'TCP'
    UDP = 'UDP'
