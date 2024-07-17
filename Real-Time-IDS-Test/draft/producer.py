import subprocess, os
from kafka import KafkaProducer

folder_raw = 'data/raw_pcap'
folder_bro = 'data/data_bro'
topic = 'logfromtcp'
path_to_bro = 'tcpdump2kdd/darpa2gurekddcup.bro'

def publish_message(producer, topic, key, value):
	try:
		if not isinstance(key, str):
			key = str(key)
		if not isinstance(key, bytes):
			key_bytes = bytes(key, encoding='utf-8')
		else:
			key_bytes = key

		if not isinstance(value, bytes):
			value_bytes = bytes(value, encoding='utf-8')
		else:
			value_bytes = value
		producer.send(topic, key=key_bytes, value=value_bytes)
		producer.flush()
		# print('Sent message to Kafka!', value)
	except Exception as e:
		raise e

def connect_producer():
	producer = KafkaProducer(bootstrap_servers=['localhost:9092'], api_version=(0, 10))
	return producer

def get_data(path):
	f = open(path, 'r')
	content = f.read()
	print(content)
	f.close()
	return content

if __name__ == '__main__':
	while True:
		'''
		Always keep the newest file because it is being processed by tcpdump
		'''
		files = [int(f.replace('.pcap','')) for f in os.listdir(folder_raw) if f != '.DS_Store']
		files.sort()
		if len(files) > 1:
			del files[-1]
			for file in files:
				file = str(file) + '.pcap'
				in_path = os.path.join(folder_raw, file)
				out_path = os.path.join(folder_bro, file.replace('.pcap','.list'))
				cmd_bro = subprocess.Popen('bro -r {} {} > {}'.format(in_path, path_to_bro, out_path),
					shell=True,stdout=subprocess.PIPE)
				(result, ignore) = cmd_bro.communicate()

				if cmd_bro.returncode == 0:
					producer = connect_producer()
					key = file.replace('.pcap', '')
					value = get_data(out_path)
					publish_message(producer, topic, key, value)
					os.remove(in_path)
					print('Delete', in_path)
				else:
					raise Exception
		