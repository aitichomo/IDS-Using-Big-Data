import os
from pyspark.sql import SQLContext, Row, SparkSession
from pyspark import SparkContext
from pyspark.sql import SparkSession, Window
from pyspark.sql.types import ArrayType, StructField, StructType, StringType, IntegerType
from pyspark.sql.functions import *
import copy

os.environ["PYSPARK_PYTHON"]="/usr/local/opt/python/bin/python3.7"
os.environ["PYSPARK_DRIVER_PYTHON"]="/usr/local/opt/python/bin/python3.7"


data = [('Category A', 170, "This is category A"),
        ('Category B', 120, "This is category B"),
        ('Category C', 150, "This is category C")]

spark = SparkSession.builder \
    .appName("TEST") \
    .master("local") \
    .getOrCreate()

schema = StructType([
    StructField('Category', StringType(), True),
    StructField('Count', IntegerType(), True),
    StructField('Description', StringType(), True)
])


rdd = spark.sparkContext.parallelize(data)

df = spark.createDataFrame(rdd)
# df = df.orderBy(df.Count)
df.show()

# dfc = spark.createDataFrame(rdd, schema)
# dfc.show()
# w = Window.partitionBy('Category')
# df.select('Count', count('Count').over(w).alias('Hola')).show()

# df.show()

# df.createGlobalTempView("dff")

# def func(x):
# 	print(x)
# 	return 6

# # func(2)
# cols = ['Name', 'Number']


# def dosth(row, df):
# 	nrow = []
# 	nrow.append(row.Category)
# 	nrow.append(df.filter(col('Count') > 130).count())

# 	return nrow
	



# udf_func = udf(func, IntegerType())

# df2 = df.withColumn('Hola', udf_func(df.Count))

# res = []
# for row in df.rdd.collect():
# 	a = dosth(row, df)
# 	res.append(a)

# df2 = spark.createDataFrame(res, cols)
# df2.show()

# df.groupBy('Category').agg(count(when(col("Count") > 130, True)),
# 							count(when(col("Count") < 130, True))).show()
# df1 = df.filter(col('Count') < 170)

# def func(x):
# 	return x

# udf_func = udf(lambda x: func(x))

# df2 = df.withColumn('New', lit(0))

# df2.show()

