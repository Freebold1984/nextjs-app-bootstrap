import os

class Config:
    # Model paths
    ML_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models/xss_model.h5')
    WORD2VEC_MODEL = os.path.join(os.path.dirname(__file__), 'models/word2vec.model')
    
    # Scanning parameters
    MAX_DEPTH = 5
    THREADS = 10
    TIMEOUT = 30
    
    # Payload configurations
    PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), 'payloads.txt')
    FUZZING_ITERATIONS = 1000
    
    # Reporting
    REPORT_FORMAT = 'html'
    MIN_CONFIDENCE = 0.85
