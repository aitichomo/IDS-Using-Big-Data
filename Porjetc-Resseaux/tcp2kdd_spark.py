import os
from pyspark.sql import SparkSession
from pyspark.sql.types import StructField, StructType, StringType, IntegerType, FloatType
from pyspark.sql.functions import *

os.environ["PYSPARK_PYTHON"]="/usr/local/opt/python/bin/python3.7"
os.environ["PYSPARK_DRIVER_PYTHON"]="/usr/local/opt/python/bin/python3.7"

def convert_tcp_to_kdd(data):
	spark = SparkSession.builder \
	    .appName("KDD") \
	    .master("local") \
	    .getOrCreate()

	schema = StructType([
	    StructField('num_conn', StringType(), True),
	    StructField('start_time', StringType(), True),
	    StructField('orig_p', StringType(), True),
	    StructField('resp_p', StringType(), True),
	    StructField('orig_h', StringType(), True),
	    StructField('resp_h', StringType(), True),
	    StructField('duration', StringType(), True),
	    StructField('protocol', StringType(), True),
	    StructField('service', StringType(), True),
	    StructField('flag', StringType(), True),
	    StructField('src_bytes', StringType(), True),
	    StructField('dst_bytes', StringType(), True),
	    StructField('land', StringType(), True),
	    StructField('wrong_fragment', StringType(), True),
	    StructField('urg', StringType(), True),
	    StructField('hot', StringType(), True),
	    StructField('num_failed_logins', StringType(), True),
	    StructField('logged_in', StringType(), True),
	    StructField('num_compromised', StringType(), True),
	    StructField('root_shell', StringType(), True),
	    StructField('su_attempted', StringType(), True),
	    StructField('num_root', StringType(), True),
	    StructField('num_file_creations', StringType(), True),
	    StructField('num_shells', StringType(), True),
	    StructField('num_access_files', StringType(), True),
	    StructField('num_outbound_cmds', StringType(), True),
	    StructField('is_hot_login', StringType(), True),
	    StructField('is_guest_login', StringType(), True)
	])

	rdd = spark.sparkContext.parallelize(data)
	df = spark.createDataFrame(rdd, schema)

	df = df.withColumn('num_conn_int', col('num_conn').cast(IntegerType()))
	df = df.drop('num_conn')
	df = df.withColumnRenamed('num_conn_int', 'num_conn')

	df = df.withColumn('start_time_float', col('start_time').cast(FloatType()))
	df = df.drop('start_time')
	df = df.withColumnRenamed('start_time_float', 'start_time')

	df = df.withColumn('duration_float', col('duration').cast(FloatType()))
	df = df.drop('duration')
	df = df.withColumnRenamed('duration_float', 'duration')

	df = df.withColumn('src_bytes_float', col('src_bytes').cast(IntegerType()))
	df = df.drop('src_bytes')
	df = df.withColumnRenamed('src_bytes_float', 'src_bytes')

	df = df.withColumn('dst_bytes_float', col('dst_bytes').cast(IntegerType()))
	df = df.drop('dst_bytes')
	df = df.withColumnRenamed('dst_bytes_float', 'dst_bytes')

	df = df.withColumn('land_int', col('land').cast(IntegerType()))
	df = df.drop('land')
	df = df.withColumnRenamed('land_int', 'land')

	df = df.withColumn('wrong_fragment_int', col('wrong_fragment').cast(IntegerType()))
	df = df.drop('wrong_fragment')
	df = df.withColumnRenamed('wrong_fragment_int', 'wrong_fragment')

	df = df.withColumn('urg_int', col('urg').cast(IntegerType()))
	df = df.drop('urg')
	df = df.withColumnRenamed('urg_int', 'urg')

	df = df.withColumn('hot_int', col('hot').cast(IntegerType()))
	df = df.drop('hot')
	df = df.withColumnRenamed('hot_int', 'hot')

	df = df.withColumn('num_failed_logins_int', col('num_failed_logins').cast(IntegerType()))
	df = df.drop('num_failed_logins')
	df = df.withColumnRenamed('num_failed_logins_int', 'num_failed_logins')

	df = df.withColumn('logged_in_int', col('logged_in').cast(IntegerType()))
	df = df.drop('logged_in')
	df = df.withColumnRenamed('logged_in_int', 'logged_in')

	df = df.withColumn('num_compromised_int', col('num_compromised').cast(IntegerType()))
	df = df.drop('num_compromised')
	df = df.withColumnRenamed('num_compromised_int', 'num_compromised')

	df = df.withColumn('root_shell_int', col('root_shell').cast(IntegerType()))
	df = df.drop('root_shell')
	df = df.withColumnRenamed('root_shell_int', 'root_shell')

	df = df.withColumn('su_attempted_int', col('su_attempted').cast(IntegerType()))
	df = df.drop('su_attempted')
	df = df.withColumnRenamed('su_attempted_int', 'su_attempted')

	df = df.withColumn('num_root_int', col('num_root').cast(IntegerType()))
	df = df.drop('num_root')
	df = df.withColumnRenamed('num_root_int', 'num_root')

	df = df.withColumn('num_file_creations_int', col('num_file_creations').cast(IntegerType()))
	df = df.drop('num_file_creations')
	df = df.withColumnRenamed('num_file_creations_int', 'num_file_creations')

	df = df.withColumn('num_shells_int', col('num_shells').cast(IntegerType()))
	df = df.drop('num_shells')
	df = df.withColumnRenamed('num_shells_int', 'num_shells')

	df = df.withColumn('num_access_files_int', col('num_access_files').cast(IntegerType()))
	df = df.drop('num_access_files')
	df = df.withColumnRenamed('num_access_files_int', 'num_access_files')

	df = df.withColumn('num_outbound_cmds_int', col('num_outbound_cmds').cast(IntegerType()))
	df = df.drop('num_outbound_cmds')
	df = df.withColumnRenamed('num_outbound_cmds_int', 'num_outbound_cmds')

	df = df.withColumn('is_hot_login_int', col('is_hot_login').cast(IntegerType()))
	df = df.drop('is_hot_login')
	df = df.withColumnRenamed('is_hot_login_int', 'is_hot_login')

	df = df.withColumn('is_guest_login_int', col('is_guest_login').cast(IntegerType()))
	df = df.drop('is_guest_login')
	df = df.withColumnRenamed('is_guest_login_int', 'is_guest_login')

	df = df.orderBy('num_conn')

	# Calculate new attributes
	derived_schema = StructType([
		StructField('num_conn', IntegerType(), True),
		StructField('counte', IntegerType(), True),
		StructField('srv_count', IntegerType(), True),
		StructField('serror_rate', FloatType(), True),
		StructField('srv_serror_rate', FloatType(), True),
		StructField('rerror_rate', FloatType(), True),
		StructField('srv_rerror_rate', FloatType(), True),
		StructField('same_srv_rate', FloatType(), True),
		StructField('diff_srv_rate', FloatType(), True),
		StructField('srv_diff_host_rate', FloatType(), True),
		StructField('dst_host_count', IntegerType(), True),
		StructField('dst_srv_host_count', IntegerType(), True),
		StructField('dst_host_same_srv_rate', FloatType(), True),
		StructField('dst_host_diff_srv_rate', FloatType(), True),
		StructField('dst_host_same_src_port_rate', FloatType(), True),
		StructField('dst_host_srv_diff_host_rate', FloatType(), True),
		StructField('dst_host_serror_rate', FloatType(), True),
		StructField('dst_host_srv_serror_rate', FloatType(), True),
		StructField('dst_host_rerror_rate', FloatType(), True),
		StructField('dst_host_srv_rerror_rate', FloatType(), True)
	])
	
	def derive_attributes(row, df):	
		count = 0
		serror = 0
		rerror = 0
		same_srv = 0
		diff_srv = 0
		srv_count = 0
		srv_serror = 0
		srv_rerror = 0
		srv_diff_host = 0
		serror_rate = 0
		rerror_rate = 0
		same_srv_rate = 0
		diff_srv_rate = 0
		srv_serror_rate = 0
		srv_rerror_rate = 0
		srv_diff_host_rate = 0

		ndf = df.filter((float(row.start_time) - col('start_time') <= 2) & (col('start_time') <= float(row.start_time)))
		
		count = ndf.filter(row.resp_h == col('resp_h')).count()
		serror = ndf.filter((row.resp_h == col('resp_h')) & ((col('flag') == 'S0')|(col('flag') == 'S1')|(col('flag') == 'S2')|(col('flag') == 'S3'))).count()
		rerror = ndf.filter((row.resp_h == col('resp_h')) & (col('flag') == 'REJ')).count()
		same_srv = ndf.filter((row.resp_h == col('resp_h')) & (col('service') != 'other') & (col('service') == row.service)).count()
		diff_srv = ndf.filter((row.resp_h == col('resp_h')) & (col('service') != row.service)).count()

		srv_count = ndf.filter(row.resp_p == col('resp_p')).count()
		srv_serror = ndf.filter((row.resp_p == col('resp_p')) & ((col('flag') == 'S0')|(col('flag') == 'S1')|(col('flag') == 'S2')|(col('flag') == 'S3'))).count()
		srv_rerror = ndf.filter((row.resp_p == col('resp_p')) & (col('flag') == 'REJ')).count()
		srv_diff_host = ndf.filter((row.resp_p == col('resp_p')) & (row.resp_h != col('resp_h'))).count()

		if count != 0:
			serror_rate = serror / count
			rerror_rate = rerror / count
			same_srv_rate = same_srv / count
			diff_srv_rate = diff_srv / count

		if srv_count != 0:
			srv_serror_rate = srv_serror / srv_count
			srv_rerror_rate = srv_rerror / srv_count
			srv_diff_host_rate = srv_diff_host / srv_count

		# dst
		dst_host_count = 0
		dst_host_serror = 0
		dst_host_rerror = 0
		dst_host_same_srv = 0
		dst_host_diff_srv = 0
		dst_srv_host_count = 0
		dst_host_srv_serror = 0
		dst_host_srv_rerror = 0
		dst_host_srv_diff_host = 0
		dst_host_same_src_port = 0
		dst_host_serror_rate = 0
		dst_host_rerror_rate = 0
		dst_host_same_srv_rate = 0
		dst_host_diff_srv_rate = 0
		dst_host_srv_serror_rate = 0
		dst_host_srv_rerror_rate = 0
		dst_host_srv_diff_host_rate = 0
		dst_host_same_src_port_rate = 0

		ddf = df.filter(col('num_conn') < row.num_conn)
		ddf = df.orderBy(df.num_conn.desc())

		len_ddf = ddf.count()
		if len_ddf > 100:
			ddf = ddf.head(100)

		dst_host_count = ddf.filter(row.resp_h == col('resp_h')).count()
		dst_host_serror = ddf.filter((row.resp_h == col('resp_h')) & ((col('flag') == 'S0')|(col('flag') == 'S1')|(col('flag') == 'S2')|(col('flag') == 'S3'))).count()
		dst_host_rerror = ddf.filter((row.resp_h == col('resp_h')) & (col('flag') == 'REJ')).count()
		dst_host_same_srv = ddf.filter((row.resp_h == col('resp_h')) & (col('service') != 'other') & (col('service') == row.service)).count()
		dst_host_diff_srv = ddf.filter((row.resp_h == col('resp_h')) & (col('service') != row.service)).count()

		dst_srv_host_count = ddf.filter(row.resp_p == col('resp_p')).count()
		dst_host_srv_serror = ddf.filter((row.resp_p == col('resp_p')) & ((col('flag') == 'S0')|(col('flag') == 'S1')|(col('flag') == 'S2')|(col('flag') == 'S3'))).count()
		dst_host_srv_rerror = ddf.filter((row.resp_p == col('resp_p')) & (col('flag') == 'REJ')).count()
		dst_host_srv_diff_host = ddf.filter((row.resp_p == col('resp_p')) & (row.resp_h != col('resp_h'))).count()

		if dst_host_count != 0:
			dst_host_serror_rate = dst_host_serror / dst_host_count
			dst_host_rerror_rate = dst_host_rerror / dst_host_count
			dst_host_same_srv_rate = dst_host_same_srv / dst_host_count
			dst_host_diff_srv_rate = dst_host_diff_srv / dst_host_count

		if dst_srv_host_count != 0:
			dst_host_srv_serror_rate = dst_host_srv_serror / dst_srv_host_count
			dst_host_srv_rerror_rate = dst_host_srv_rerror / dst_srv_host_count
			dst_host_srv_diff_host_rate = dst_host_srv_diff_host / dst_srv_host_count

		if len_ddf != 0:
			dst_host_same_src_port_rate = dst_host_same_src_port / len_ddf

		return [
			row.num_conn,
			count, 
			srv_count, 
			float(serror_rate), 
			float(srv_serror_rate), 
			float(rerror_rate), 
			float(srv_rerror_rate), 
			float(same_srv_rate), 
			float(diff_srv_rate),
			float(srv_diff_host_rate), 
			dst_host_count, 
			dst_srv_host_count, 
			float(dst_host_same_srv_rate), 
			float(dst_host_diff_srv_rate), 
			float(dst_host_same_src_port_rate), 
			float(dst_host_srv_diff_host_rate), 
			float(dst_host_serror_rate), 
			float(dst_host_srv_serror_rate), 
			float(dst_host_rerror_rate),
			float(dst_host_srv_rerror_rate)
		]

	derived_data = []

	ttdf = df.select('num_conn', 'start_time', 'resp_p', 'orig_p', 'resp_h', 'orig_h', 'service', 'flag')
	for row in ttdf.rdd.collect():
		derived_values = derive_attributes(row, ttdf)
		derived_data.append(derived_values)

	assert len(derived_data) == len(data)
	derived_rdd = spark.sparkContext.parallelize(derived_data)
	nddf = spark.createDataFrame(derived_rdd, derived_schema)

	res_df = df.join(nddf, df.num_conn == nddf.num_conn).select(
		df.num_conn, 
		df.resp_h,
		df.resp_p,
		df.orig_h,
		df.orig_p,
		df.protocol, # 5
		df.duration, 
		df.protocol, 
		df.service, 
		df.flag, 
		df.src_bytes,
		df.dst_bytes,
		df.land,
		df.wrong_fragment,
		df.urg,
		df.hot,
		df.num_failed_logins,
		df.logged_in,
		df.num_compromised,
		df.root_shell,
		df.su_attempted,
		df.num_root,
		df.num_file_creations,
		df.num_shells,
		df.num_access_files,
		df.num_outbound_cmds,
		df.is_hot_login,
		df.is_guest_login,
		nddf.counte,
		nddf.srv_count,
		nddf.serror_rate,
		nddf.srv_serror_rate,
		nddf.rerror_rate,
		nddf.srv_rerror_rate,
		nddf.same_srv_rate,
		nddf.diff_srv_rate,
		nddf.srv_diff_host_rate,
		nddf.dst_host_count,
		nddf.dst_srv_host_count,
		nddf.dst_host_same_srv_rate,
		nddf.dst_host_diff_srv_rate,
		nddf.dst_host_same_src_port_rate, 
		nddf.dst_host_srv_diff_host_rate, 
		nddf.dst_host_serror_rate, 
		nddf.dst_host_srv_serror_rate, 
		nddf.dst_host_rerror_rate,
		nddf.dst_host_srv_rerror_rate
	)

	res_pd = res_df.toPandas()
	label_pd = res_pd.iloc[:, :6]
	kdd_pd = res_pd.iloc[:, 6:]	

	return label_pd, kdd_pd

