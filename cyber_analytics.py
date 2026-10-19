
import os
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

# Configure Java
os.environ["JAVA_HOME"] = r"C:\Program Files\Java\jdk1.8.0_202"

# Start Spark
spark = (
    SparkSession.builder
    .appName("CyberSecurityLogAnalytics")
    .master("local[*]")
    .config("spark.hadoop.fs.defaultFS", "hdfs://localhost:9000")
    .getOrCreate()
)

spark.sparkContext.setLogLevel("WARN")

# Existing HDFS dataset
hdfs_file = (
    "hdfs://localhost:9000/"
    "cybersecurity/raw/"
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

try:
    print("\nReading cybersecurity dataset from HDFS...")

    df = (
        spark.read
        .option("header", "true")
        .option("inferSchema", "true")
        .option("mode", "PERMISSIVE")
        .csv(hdfs_file)
    )

    # Clean whitespace from column names.
    for old_name in df.columns:
        new_name = old_name.strip()
        if old_name != new_name:
            df = df.withColumnRenamed(old_name, new_name)

    print("\nDataset schema:")
    df.printSchema()

    print("\nTotal records:")
    print(df.count())

    print("\nColumn names:")
    print(df.columns)

    # Inspect traffic labels.
    if "Label" in df.columns:
        print("\nTraffic distribution:")

        (
            df.groupBy("Label")
            .count()
            .orderBy(F.desc("count"))
            .show(50, truncate=False)
        )

        print("\nBenign versus malicious traffic:")

        traffic_summary = (
            df.withColumn(
                "TrafficType",
                F.when(
                    F.upper(F.trim(F.col("Label"))) == "BENIGN",
                    "Benign"
                ).otherwise("Potentially Malicious")
            )
            .groupBy("TrafficType")
            .count()
        )

        traffic_summary.show(truncate=False)

        # Save the summary to HDFS.
        output_path = (
            "hdfs://localhost:9000/cybersecurity/results/traffic_summary"
        )

        (
            traffic_summary
            .coalesce(1)
            .write
            .mode("overwrite")
            .option("header", "true")
            .csv(output_path)
        )

        print(f"Traffic summary saved to HDFS: {output_path}")
        print("Traffic summary saved to:", output_path)
        print("\nTraffic summary saved to HDFS.")

    else:
        print("\nWARNING: The expected Label column was not found.")
        print("Inspect the schema and update the column name.")

except Exception as e:
    print("\nAnalytics failed:")
    print(str(e))
    raise

finally:
    spark.stop()
