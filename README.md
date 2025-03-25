# 🛡️ PhishDetect: Machine Learning Phishing Website Detection

## Overview

PhishDetect is an advanced machine learning application designed to detect phishing websites using a sophisticated ensemble of machine learning models. The system combines Random Forest, Support Vector Machine (SVM), and Neural Network techniques to provide robust and accurate phishing detection.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Machine Learning](https://img.shields.io/badge/ML-Ensemble%20Learning-green)
![Streamlit](https://img.shields.io/badge/Web%20App-Streamlit-red)

## 🚀 Features

- **Multi-Model Approach**: Combines Random Forest, SVM, and Neural Network models
- **Comprehensive URL Analysis**: Extracts and analyzes multiple features from URLs and website content
- **Interactive Web Interface**: Streamlit-based application for easy URL checking
- **Detailed Risk Assessment**: Provides risk levels and confidence scores
- **Model Training Capabilities**: Allow users to train models with custom URL datasets

## 🔍 How It Works

The system works by analyzing URLs through multiple stages:

1. **URL Feature Extraction**
   - Analyze URL structure
   - Check domain characteristics
   - Identify suspicious patterns

2. **Website Content Analysis**
   - Scrape and parse HTML content
   - Detect potentially malicious elements
   - Extract content-based features

3. **Machine Learning Prediction**
   - Random Forest: Handles complex feature interactions
   - SVM: Finds optimal decision boundaries
   - Neural Network: Learns intricate patterns
   - Ensemble method combines predictions for robust results

## 📦 Prerequisites

- Python 3.8+
- Libraries: 
  - scikit-learn
  - pandas
  - numpy
  - tensorflow
  - streamlit
  - requests
  - beautifulsoup4
  - tldextract

## 🛠️ Installation/Set Up

1. Clone the repository:
```bash
git clone https://github.com/yourusername/phishdetect.git
cd phishdetect
```

2. Create a virtual environment (optional):
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🚀 Running the Application

### Training Models
```bash
streamlit run streamlit_app.py
```

Navigate to the "Train Models" tab and upload CSV files containing legitimate and phishing URLs to train the models.

### Checking URLs
After training, use the "Check URL" tab to analyze potential phishing websites.

## 🧠 Model Performance

The ensemble model provides:
- High accuracy in detecting phishing websites
- Robust performance across different URL types
- Adaptive risk scoring
