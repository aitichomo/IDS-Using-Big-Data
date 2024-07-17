import pandas as pd
import tensorflow as tf
import pickle
import numpy as np
from kafka import KafkaConsumer
from producer import publish_message
from producer import connect_producer
from producer import topic
from tcp2kdd import convert_tcp_to_kdd
from dl_src.preprocessing import pre_data, get_label_dict

def load_models():
	print('Loading models from files...', end='')
	model_1 = tf.keras.models.load_model('dl_src/models/model_1.h5')
	model_2 = tf.keras.models.load_model('dl_src/models/model_2.h5')
	rf_model = pickle.load(open('dl_src/models/rf_model.sav', 'rb'))
	print('Done')
	return model_1, model_2, rf_model

def predict(model_1, model_2, rf_model, data):

	df = pd.DataFrame(data)

	results = []
	in_data = pre_data(df)
	for i in range(len(in_data)):    
		predictions = model_1.predict(np.array([in_data[i]]))
		predictions = model_2.predict(predictions)
		predictions = rf_model.predict(predictions)
  
		label_dict = get_label_dict()
		predicted_label = 'normal'
		for key, value in label_dict.items():
		  	if value == predictions[0]:
		  		predicted_label = key
		  		break
		results.append(predicted_label)
	return results

if __name__ == '__main__':
	consumer = KafkaConsumer(topic, auto_offset_reset='earliest',
							bootstrap_servers=['localhost:9092'],
							api_version=(0,10),
							consumer_timeout_ms=1000)

	md1, md2, md3 = load_models()


	for msg in consumer:
		key = (msg.key).decode()
		print(key)
		values = (msg.value).decode()
		values = values.split('\n')
		del values[-1] # last element is empty string

		kdd = convert_tcp_to_kdd(values)
		
		labels = predict(md1, md2, md3, kdd)
		
		assert len(values) == len(labels)
		N = len(values)
		for i in range(N):
			values[i] += ' {}'.format(labels[i])

		print(values)
