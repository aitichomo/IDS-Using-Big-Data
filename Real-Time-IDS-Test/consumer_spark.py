import time
import subprocess
import tensorflow as tf
import pickle
import numpy as np
import pandas as pd
from kafka import KafkaConsumer, KafkaProducer
from tcp2kdd_spark import convert_tcp_to_kdd
from dl_src.preprocessing import pre_data, get_label_dict

PATH_TO_PCAP = 'data/logfromkafka/batch.pcap'
PATH_TO_ZEEK = 'data/logfromkafka/data'
BATCH_SIZE = 50
TIMEOUT = 120
TOPIC_SEND_BACK = 'warninglog'
TOPIC_PCAP_LOG = 'logfromsnort'
PATH_TO_MODEL_1 = 'dl_src/models/model_1.h5'
PATH_TO_MODEL_2 = 'dl_src/models/model_2.h5'
PATH_TO_MODEL_RF = 'dl_src/models/rf_model.sav'

def load_models():
	print('Loading models from files...', end='')
	model_1 = tf.keras.models.load_model(PATH_TO_MODEL_1)
	model_2 = tf.keras.models.load_model(PATH_TO_MODEL_2)
	rf_model = pickle.load(open(PATH_TO_MODEL_RF, 'rb'))
	print('Done')
	return model_1, model_2, rf_model

def predict(model_1, model_2, rf_model, data):
	results = []
	in_data = pre_data(data)
	predictions = model_1.predict(np.array(in_data))
	predictions = model_2.predict(predictions)
	predictions = rf_model.predict(predictions)

	label_dict = get_label_dict()
	for p in predictions:
		predicted_label = 'normal'
		for key, value in label_dict.items():
	  		if value == p:
	  			predicted_label = key
	  			break
		results.append(predicted_label)
	return results

def convert_pcap_to_txt():
	cmd = subprocess.Popen("zeek -r tcpdump2kdd/zozo.pcap tcpdump2kdd/darpa2gurekddcup.bro",
		shell=True, stdout=subprocess.PIPE)
	result, ignorer = cmd.communicate()
	if cmd.returncode == 0:
		return result
	else:
		raise Exception

def write_pcap(data):
	f = open(PATH_TO_PCAP, 'wb')
	f.writelines(pcaps)
	f.close()

def convert_data_to_list(data):
	data = data.decode()
	data = data.split('\n')
	del data[-1]
	result = []
	for line in data:
		line = line.split(' ')
		result.append(line)
	return result

def assign_labels_to_data(labels, df):
	data = df.values.tolist()
	assert len(labels) == len(data)

	sdata = []
	for i, row in enumerate(data):
		srow = [str(x) for x in row]
		srow.append(labels[i])
		sdata.append(srow)

	lb = [' '.join(x) for x in sdata]
	return lb

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

if __name__ == '__main__':
	consumer = KafkaConsumer(TOPIC_PCAP_LOG, 
		auto_offset_reset='earliest',
		bootstrap_servers=['localhost:9092'],
		api_version=(0,10),
		consumer_timeout_ms=1000)

	# Load tensorflow models
	md1, md2, md3 = load_models()

	batch_number = 0
	sample_number = 0
	while True:
		batch_number += 1
		print('Processing batch number {}...'.format(batch_number))
		batch = consumer.poll(TIMEOUT, BATCH_SIZE)
		# print(batch)
		pcaps = []
		if batch:
			# get pcaps
			values = batch.values()
			values = list(values)
			for value in values:
				for record in value:
					print('Reading record number {}...'.format(record.key.decode()))
					pcaps.append(record.value)

			write_pcap(pcaps)
			data = convert_pcap_to_txt()
			data = convert_data_to_list(data)
			label_kdd, kdd_pd = convert_tcp_to_kdd(data)
			# print(kdd_pd)
			labels = predict(md1, md2, md3, kdd_pd)
			data = assign_labels_to_data(labels, label_kdd)

			# send back to kafka
			producer = connect_producer()
			for row in data:
				sample_number += 1
				publish_message(producer, TOPIC_SEND_BACK, sample_number, row)

	consumer.close()
