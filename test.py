import joblib

pipeline = joblib.load('/Users/fairuznawar/Desktop/rf_pipeline.pkl')
print("Loaded steps:", pipeline.named_steps)
