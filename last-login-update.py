from ldap3 import Server, Connection, SASL, KERBEROS, ALL, MODIFY_REPLACE
from datetime import datetime, timedelta

####################################################
server_address = 'ldap://name.domain.local' #change this
base_dn = 'DC=domain,DC=local' #change this
####################################################

def header():
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%&%%%%&&%%&&%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@@@@#*@@@@@@@.@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%&@@ .@@.@@@.....&.@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%%%%%%%%@@@@@*@@...............@@/@@@@@%%%%%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%%%&@@@@*////@@ ..@@@@@@@@.....#@#/////@@@@%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%@@@**********@@. @@@@@@@@.....@@//////////@@@%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%@@@************@@..@@@ @@@........@@////////////@@@%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%@@@**************@@.,@@@@@@@....... @@//////////////@@@%%%%%%%%%%%%")
    print("%%%%%%%%%%%@@@******************@@.@@@@@@......@@//////////////////@@%%%%%%%%%%%")
    print("%%%%%%%%%%@@*********************@@.@@@@@.....@@////////////////////#@@%%%%%%%%%")
    print("%%%%%%%%%@@****************,,,,*@@..@. @@......@@/////////////////////@@%%%%%%%%")
    print("%%%%%%%%@@*********,*,,,,,,,*@@@@.@* @@......&. @@@@///////////////////@@%%%%%%%")
    print("%%%%%%%@@***,,,,,,,,,,,@@@@@*@@@..@/*..@@@..@*/......@@@@&//////////////@@%%%%%%")
    print("%%%%%%&@@,,,,,,,,,,*@@@@@@//////(.@/*. .@....//...........&@@*//////////@@%%%%%%")
    print("%%%%%%@@,,,,,,,,,,@@@@///////////,..////,////................@@//////////@@%%%%%")
    print("%%%%%%@@,,,,,,,,,@@(////.///////////////@(////*...............@@/////////@@%%%%%")
    print("%%%%%%@@,,,,,,,,,@@//////..///////////////////*.........*.....@@/////////@@%%%%%")
    print("%%%%%%@@,,,,,,,,,@@// .......///////////@////*.........**.....@@*******/*@@%%%%%")
    print("&%&%&%&@#,,,,....@&*.@@@@@&.,@%..///////////..........,,......@@********@@%%&%%%")
    print("%%%%%%%@@,,......@#. ....(@@@@@@@@ ..,....../@@@@@@@@@........@@********@@%%&%%%")
    print("&&%%%%%%@@.......@#.///,..........&@@@@@@@@@@@@@@#............@@*******@@%&&%%%%")
    print("&%%%%%%%%@@......@(../ .@&//..@@@@@@@@@@@@@......@@..*/@@..*..@@******@@%%%%%%%%")
    print("%%%%%%%%%%@@.....@#./. @///.,@@@@@@@@.. @...,@@@@@@@&.///@..*.@@*****@@%%%%%%%%%")
    print("%%%%%%%%%%%@@@...@@.(.&///*.@@....*@........@@....*@@..///(...@@***@@@%%%%%%%%%%")
    print("%%%%%%%%%%%%%@@&..#@@.,///,..@(...................@@...///,.@@@**@@@%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%@@@...@@@@@@@.........................#@@@@@@*,,@@@%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%@@@.....@@....,....................@@,,,,,@@@%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%%%%@@@%.@@.........................@@*@@&@%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%%%%%%%%@@@&&.....................@@@@&%%%%%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%&&&&&&&&&&&&&&&&&%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")


# Function to convert Windows File Time to datetime
def convert_windows_time_to_date(windows_time):
    if windows_time:
        epoch_start = datetime(1601, 1, 1)
        return epoch_start + timedelta(microseconds=int(windows_time) / 10)
    return None

# Function to retrieve the last login by int and convert to string then update the custom attribute
def update_last_login_string(server_address, base_dn):
    try:
        server = Server(server_address, get_info=ALL)
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
        conn.search(base_dn, '(objectClass=user)', attributes=['distinguishedName', 'lastLogon'])
        for entry in conn.entries: #loop over objects
            dn          = entry.distinguishedName.value
            last_logon  = entry.lastLogon.value
            if isinstance(last_logon, datetime):
                last_logon_date = last_logon
            else:
                last_logon_date = convert_windows_time_to_date(last_logon) if last_logon else None
            # Get lastLoginString value
            last_logon_string = last_logon_date.strftime('%Y-%m-%d %H:%M:%S') if last_logon_date else 'Never Logged In'
            # Update the user's lastLoginString
            conn.modify(dn, {'lastLoginString': [(MODIFY_REPLACE, [last_logon_string])]})
            print(f"Updated {dn} with lastLoginString: {last_logon_string}")
        conn.unbind()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    header()
    update_last_login_string(server_address, base_dn)
