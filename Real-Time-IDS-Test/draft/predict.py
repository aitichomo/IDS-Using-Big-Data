import pandas as pd
import tensorflow as tf
import pickle
import numpy as np
from dl_src.preprocessing import pre_data, get_label_dict

def predict(data):
  print('Loading models from files...', end='')
  model_1 = tf.keras.models.load_model('dl_src/models/model_1.h5')
  model_2 = tf.keras.models.load_model('dl_src/models/model_2.h5')
  rf_model = pickle.load(open('dl_src/models/rf_model.sav', 'rb'))
  print('Done')

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

    
  