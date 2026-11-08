"""Train and evaluate on user-supplied, labelled HTTP-input data.

CSV columns: text,label (0=benign,1=malicious). No network downloads.
Keep a separate test split; select the threshold ONLY on validation.
Do not enable enforcement until the false-positive rate is acceptable.
"""
import argparse
import json
from datetime import datetime,timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT=Path(__file__).resolve().parent


def evaluate(labels,scores,threshold):
    preds=(scores>=threshold).astype(int)
    tn,fp,fn,tp=(int(v) for v in confusion_matrix(labels,preds,labels=[0,1]).ravel())
    prec,rec,f1,_=precision_recall_fscore_support(labels,preds,average='binary',zero_division=0)
    return {'tp':tp,'tn':tn,'fp':fp,'fn':fn,
            'fpr':round(fp/max(1,fp+tn),5),
            'fnr':round(fn/max(1,fn+tp),5),
            'precision':round(float(prec),5),
            'recall':round(float(rec),5),
            'f1':round(float(f1),5)}


def train(path,threshold_goal=0.03):
    data=pd.read_csv(path,keep_default_na=False)
    if not {'text','label'}.issubset(data.columns):
        raise ValueError('CSV needs columns text,label (0 benign / 1 malicious)')
    data['label']=data['label'].map(lambda x: str(x).strip().lower()).map(
        {'0':0,'1':1,'benign':0,'malicious':1})
    if data['label'].isna().any():
        raise ValueError('Unexpected labels: only 0,1,benign,malicious are accepted')
    data=data[(data['text'].str.len()>0)&(data['text'].str.len()<=4096)].drop_duplicates('text')
    counts=data['label'].value_counts()
    if len(counts)<2 or counts.min()<15:
        raise ValueError('Need >=15 distinct benign and >=15 distinct malicious texts')
    X=data['text'].tolist()
    y=data['label'].astype(int).to_numpy()
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.20,random_state=42,stratify=y)
    X_train,X_val,y_train,y_val=train_test_split(X_train,y_train,test_size=.25,random_state=42,stratify=y_train)
    model=Pipeline([
        ('vectorizer',TfidfVectorizer(analyzer='char',ngram_range=(3,5),max_features=20000,sublinear_tf=True)),
        ('classifier',LogisticRegression(class_weight='balanced',max_iter=1500,random_state=42))
    ])
    model.fit(X_train,y_train)
    val_scores=model.predict_proba(X_val)[:,1]
    candidates=[round(i/1000,3) for i in range(500,1001)]
    valid=[(t,evaluate(y_val,val_scores,t)) for t in candidates if evaluate(y_val,val_scores,t)['fpr']<=threshold_goal]
    # Maximise validation recall under FP constraint; ties prefer high threshold.
    threshold=sorted(valid,key=lambda z:(z[1]['recall'],z[0]),reverse=True)[0][0] if valid else 1.0
    test_scores=model.predict_proba(X_test)[:,1]
    report={
        'data_file':str(path),'sample_count':len(data),
        'counts':{'benign':int(counts.get(0,0)),'malicious':int(counts.get(1,0))},
        'split':{'train':len(X_train),'validation':len(X_val),'test':len(X_test)},
        'target_fpr':threshold_goal,'selected_threshold':threshold,
        'validation':evaluate(y_val,val_scores,threshold),
        'held_out_test':evaluate(y_test,test_scores,threshold),
        'warning':('Small or synthetic datasets do not establish real-world FPR. '
                   'Inspect genuine benign false positives before enabling enforce mode.'),
        'created_at':datetime.now(timezone.utc).isoformat(),
    }
    artifacts=ROOT/'artifacts'
    artifacts.mkdir(exist_ok=True)
    joblib.dump(model,artifacts/'waf_model.joblib')
    (artifacts/'ml_report.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
    return report


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--csv',type=Path,required=True)
    parser.add_argument('--target-fpr',type=float,default=.03)
    args=parser.parse_args()
    if not 0<=args.target_fpr<=1:
        parser.error('--target-fpr must be between 0 and 1')
    train(args.csv,args.target_fpr)


if __name__=='__main__':
    main()
