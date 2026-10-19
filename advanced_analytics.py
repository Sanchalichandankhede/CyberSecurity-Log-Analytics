import os

os.environ["JAVA_HOME"] = r"C:\Program Files\Java\jdk1.8.0_202"

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

# Initialize Spark
spark = (
    SparkSession.builder
    .appName("CyberSecurityAdvancedAnalytics")
    .master("local[*]")
    .getOrCreate()
)

# Load dataset from HDFS
input_path = (
    "hdfs://localhost:9000/cybersecurity/raw/"
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

df = (
    spark.read
    .option("header", "true")
    .option("inferSchema", "true")
    .option("mode", "PERMISSIVE")
    .csv(input_path)
)

# Clean column names
for old_name in df.columns:
    new_name = old_name.strip()
    if old_name != new_name:
        df = df.withColumnRenamed(old_name, new_name)

# Normalize labels and trim whitespace
df = df.withColumn(
    "Label",
    F.trim(F.col("Label").cast("string"))
)

# Output directory
base_path = "hdfs://localhost:9000/cybersecurity/results"

# 1. Traffic classification summary
traffic_summary = (
    df.withColumn(
        "TrafficType",
        F.when(
            F.upper(F.col("Label")) == "BENIGN",
            "Benign"
        ).otherwise("Potentially Malicious")
    )
    .groupBy("TrafficType")
    .count()
)

traffic_summary.coalesce(1).write.mode("overwrite").option(
    "header", "true"
).csv(base_path + "/traffic_summary_advanced")

# 2. Top destination ports by flow count
top_ports = (
    df.groupBy("Destination Port")
    .count()
    .orderBy(F.desc("count"))
    .limit(15)
)

top_ports.coalesce(1).write.mode("overwrite").option(
    "header", "true"
).csv(base_path + "/top_destination_ports")

# 3. Attack label distribution
attack_distribution = (
    df.groupBy("Label")
    .count()
    .orderBy(F.desc("count"))
)

attack_distribution.coalesce(1).write.mode("overwrite").option(
    "header", "true"
).csv(base_path + "/attack_distribution")

# 4. Traffic statistics by label
traffic_statistics = (
    df.groupBy("Label")
    .agg(
        F.count("*").alias("FlowCount"),
        F.avg("Flow Duration").alias("AverageFlowDuration"),
        F.avg("Total Fwd Packets").alias("AverageForwardPackets"),
        F.avg("Total Backward Packets").alias("AverageBackwardPackets")
    )
    .orderBy(F.desc("FlowCount"))
)

traffic_statistics.coalesce(1).write.mode("overwrite").option(
    "header", "true"
).csv(base_path + "/traffic_statistics")

# 5. High SYN flag flows by label
syn_analysis = (
    df.groupBy("Label")
    .agg(
        F.avg("SYN Flag Count").alias("AverageSYNFlagCount"),
        F.avg("RST Flag Count").alias("AverageRSTFlagCount"),
        F.count("*").alias("FlowCount")
    )
    .orderBy(F.desc("AverageSYNFlagCount"))
)

syn_analysis.coalesce(1).write.mode("overwrite").option(
    "header", "true"
).csv(base_path + "/flag_analysis")

print("Advanced analytics completed successfully.")

print("Results saved under:")
print(base_path)

spark.stop()