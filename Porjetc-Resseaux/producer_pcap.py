import subprocess, os
import time
from kafka import KafkaProducer

TOPIC_NAME = 'logfromsnort'
# key = 'pcaplog'
PATH_TO_LOGS = 'snort/logs'
PATH_TO_FILENAMES = 'snort/read_logs.txt'

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
		print('Publish message number {}...'.format(key))
	except Exception as e:
		raise e

def connect_producer():
	producer = KafkaProducer(bootstrap_servers=['localhost:9092'], api_version=(0, 10))
	return producer

if __name__ == '__main__':
	filenames = []
	fn = open(PATH_TO_FILENAMES, 'r')
	content = fn.read()
	if content:
		filenames = content.split('\n')
		del filenames[-1]
	fn.close()

	key = 0
	while True:
		for file in os.listdir(PATH_TO_LOGS):	
			if file not in filenames:
				print('Processing file {}'.format(file))
				f = open(os.path.join(PATH_TO_LOGS, file), 'rb')
				producer = connect_producer()

				is_nothing = True
				count = 0 # program will end after 10 times of reading nothing
				while True:
					eof = f.tell()
					line = f.readline()
					if not line:
						time.sleep(1)
						f.seek(eof)
						if is_nothing:
							count += 1
							if count == 10:
								break
						else:
							is_nothing = True
					else:
						key += 1
						publish_message(producer, TOPIC_NAME, key, line)
						is_nothing = False
						count = 0

				f.close()

				fn = open('snort/read_logs.txt', 'a')
				fn.write(file + '\n')
				fn.close()
	

