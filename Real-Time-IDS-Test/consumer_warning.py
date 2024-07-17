from kafka import KafkaConsumer

TOPIC_WARNING = 'warninglog'

if __name__ == '__main__':
	consumer = KafkaConsumer(TOPIC_WARNING, auto_offset_reset='earliest',
							bootstrap_servers=['localhost:9092'],
							api_version=(0,10),
							consumer_timeout_ms=1000)
	while True:
		for msg in consumer:
			key = (msg.key).decode()
			values = (msg.value).decode()
			values = values.split(' ')
			print('Warning: (IP {}, port {}) -> (IP {}, port {}), protocl {}: {}'
				.format(values[3], values[4], values[1], values[2], values[5], values[6]))