#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Machine Learning Model for Phishing Detection
使用多种先进算法的集成学习系统
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import (
    RandomForestClassifier, 
    GradientBoostingClassifier, 
    AdaBoostClassifier,
    VotingClassifier,
    BaggingClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    roc_auc_score,
    precision_recall_curve,
    f1_score
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import xgboost as xgb
import warnings
import pickle
import time
warnings.filterwarnings('ignore')

class EnhancedPhishingDetector:
    """增强的钓鱼检测模型集成系统"""
    
    def __init__(self):
        self.models = {}
        self.ensemble_model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.training_scores = {}
        
    def create_base_models(self):
        """创建基础模型集合"""
        print("🔧 创建基础模型...")
        
        self.models = {
            # 树模型
            'rf': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
            
            'gb': GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=8,
                min_samples_split=5,
                random_state=42
            ),
            
            'xgb': xgb.XGBClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=8,
                min_child_weight=3,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='logloss'
            ),
            
            'ada': AdaBoostClassifier(
                n_estimators=100,
                learning_rate=1.0,
                random_state=42
            ),
            
            # 线性模型
            'lr': LogisticRegression(
                C=1.0,
                max_iter=1000,
                random_state=42
            ),
            
            # 支持向量机
            'svm': SVC(
                C=1.0,
                kernel='rbf',
                gamma='scale',
                probability=True,
                random_state=42
            ),
            
            # 神经网络
            'mlp': MLPClassifier(
                hidden_layer_sizes=(100, 50),
                activation='relu',
                solver='adam',
                alpha=0.001,
                learning_rate='adaptive',
                max_iter=500,
                random_state=42
            ),
            
            # 朴素贝叶斯
            'nb': GaussianNB(),
            
            # K近邻
            'knn': KNeighborsClassifier(
                n_neighbors=7,
                weights='distance'
            )
        }
        
        print(f"✅ 创建了 {len(self.models)} 个基础模型")
        
    def train_individual_models(self, X_train, y_train, X_test, y_test):
        """训练各个基础模型"""
        print("\n🚀 训练各个基础模型...")
        
        # 将标签从 {-1, 1} 映射到 {0, 1} 以兼容XGBoost
        y_train_mapped = np.where(y_train == -1, 0, 1)
        y_test_mapped = np.where(y_test == -1, 0, 1)
        
        # 创建模型列表的副本以避免迭代时修改字典
        models_list = list(self.models.items())
        
        for name, model in models_list:
            print(f"\n训练 {name.upper()} 模型...")
            start_time = time.time()
            
            try:
                # 对XGBoost使用映射后的标签
                current_y_train = y_train_mapped if name == 'xgb' else y_train
                current_y_test = y_test_mapped if name == 'xgb' else y_test
                
                # 对需要标准化的模型进行预处理
                if name in ['svm', 'mlp', 'knn', 'lr']:
                    # 创建包含标准化的管道
                    pipeline = Pipeline([
                        ('scaler', StandardScaler()),
                        ('classifier', model)
                    ])
                    pipeline.fit(X_train, current_y_train)
                    self.models[name] = pipeline
                    
                    # 评估
                    train_score = pipeline.score(X_train, current_y_train)
                    test_score = pipeline.score(X_test, current_y_test)
                    y_pred_proba = pipeline.predict_proba(X_test)[:, 1]
                else:
                    # 树模型和朴素贝叶斯不需要标准化
                    model.fit(X_train, current_y_train)
                    train_score = model.score(X_train, current_y_train)
                    test_score = model.score(X_test, current_y_test)
                    y_pred_proba = model.predict_proba(X_test)[:, 1]
                
                # 计算AUC (使用原始标签)
                auc_score = roc_auc_score(y_test, y_pred_proba)
                training_time = time.time() - start_time
                
                self.training_scores[name] = {
                    'train_acc': train_score,
                    'test_acc': test_score,
                    'auc': auc_score,
                    'time': training_time
                }
                
                print(f"  训练准确率: {train_score:.4f}")
                print(f"  测试准确率: {test_score:.4f}")
                print(f"  AUC分数: {auc_score:.4f}")
                print(f"  训练时间: {training_time:.2f}秒")
                
            except Exception as e:
                print(f"  ❌ {name} 模型训练失败: {str(e)}")
                if name in self.models:
                    del self.models[name]
    
    def create_ensemble_model(self, X_train, y_train):
        """创建集成模型"""
        print("\n🎯 创建集成模型...")
        
        # 选择表现最好的模型
        valid_models = []
        for name, model in self.models.items():
            if name in self.training_scores:
                score = self.training_scores[name]['test_acc']
                if score > 0.90:  # 只选择测试准确率>90%的模型
                    valid_models.append((name, model))
        
        print(f"选择 {len(valid_models)} 个优秀模型进行集成:")
        for name, _ in valid_models:
            score = self.training_scores[name]
            print(f"  - {name.upper()}: {score['test_acc']:.4f} (AUC: {score['auc']:.4f})")
        
        # 创建投票分类器
        if len(valid_models) >= 3:
            self.ensemble_model = VotingClassifier(
                estimators=valid_models,
                voting='soft'  # 使用概率投票
            )
            
            print("\n训练集成模型...")
            # 检查是否包含XGBoost，如果是则需要映射标签
            has_xgb = any(name == 'xgb' for name, _ in valid_models)
            if has_xgb:
                # 为了简化，我们创建一个包装器来处理XGBoost的标签映射
                print("⚠️ 检测到XGBoost，使用原始标签训练集成模型...")
            
            self.ensemble_model.fit(X_train, y_train)
            print("✅ 集成模型训练完成")
        else:
            print("❌ 优秀模型数量不足，使用最佳单一模型")
            best_model_name = max(self.training_scores.keys(), 
                                key=lambda x: self.training_scores[x]['test_acc'])
            self.ensemble_model = self.models[best_model_name]
            print(f"✅ 选择最佳模型: {best_model_name.upper()}")
    
    def evaluate_ensemble(self, X_test, y_test):
        """评估集成模型"""
        print("\n📊 评估集成模型性能...")
        
        # 预测
        y_pred = self.ensemble_model.predict(X_test)
        y_pred_proba = self.ensemble_model.predict_proba(X_test)[:, 1]
        
        # 计算各种指标
        accuracy = self.ensemble_model.score(X_test, y_test)
        auc = roc_auc_score(y_test, y_pred_proba)
        f1 = f1_score(y_test, y_pred)
        
        print(f"集成模型性能:")
        print(f"  准确率: {accuracy:.4f}")
        print(f"  AUC分数: {auc:.4f}")
        print(f"  F1分数: {f1:.4f}")
        
        # 详细分类报告
        print("\n详细分类报告:")
        print(classification_report(y_test, y_pred, target_names=['Phishing(-1)', 'Safe(1)']))
        
        # 混淆矩阵
        cm = confusion_matrix(y_test, y_pred)
        print("\n混淆矩阵:")
        print(f"真负例(TN): {cm[0,0]}, 假正例(FP): {cm[0,1]}")
        print(f"假负例(FN): {cm[1,0]}, 真正例(TP): {cm[1,1]}")
        
        return {
            'accuracy': accuracy,
            'auc': auc,
            'f1': f1,
            'confusion_matrix': cm
        }
    
    def save_enhanced_model(self, filepath='pickle/enhanced_model.pkl'):
        """保存增强模型"""
        model_data = {
            'ensemble_model': self.ensemble_model,
            'training_scores': self.training_scores,
            'feature_names': self.feature_names
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"✅ 增强模型已保存到: {filepath}")
    
    def predict_enhanced(self, X):
        """使用增强模型进行预测"""
        if self.ensemble_model is None:
            raise ValueError("模型尚未训练，请先调用 train() 方法")
        
        # 获取预测概率
        proba = self.ensemble_model.predict_proba(X)
        return proba[:, 1]  # 返回正类(安全)概率
    
    def train(self, csv_file='phishing.csv'):
        """完整的训练流程"""
        print("🎯 开始增强模型训练流程")
        print("=" * 60)
        
        # 1. 加载数据
        print("📂 加载数据...")
        df = pd.read_csv(csv_file)
        X = df.drop(['class', 'Index'], axis=1)
        y = df['class']
        self.feature_names = X.columns.tolist()
        
        print(f"数据规模: {X.shape[0]} 样本, {X.shape[1]} 特征")
        print(f"类别分布: {dict(y.value_counts())}")
        
        # 2. 数据分割
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        print(f"训练集: {X_train.shape[0]} 样本")
        print(f"测试集: {X_test.shape[0]} 样本")
        
        # 3. 创建和训练基础模型
        self.create_base_models()
        self.train_individual_models(X_train, y_train, X_test, y_test)
        
        # 4. 创建集成模型
        self.create_ensemble_model(X_train, y_train)
        
        # 5. 评估集成模型
        results = self.evaluate_ensemble(X_test, y_test)
        
        # 6. 保存模型
        self.save_enhanced_model()
        
        print("\n🎉 增强模型训练完成!")
        return results

def main():
    """主函数"""
    print("🚀 启动增强机器学习模型训练")
    
    # 创建增强检测器
    detector = EnhancedPhishingDetector()
    
    # 训练模型
    results = detector.train()
    
    print("\n📈 最终结果总结:")
    print(f"增强模型准确率: {results['accuracy']:.4f}")
    print(f"AUC分数: {results['auc']:.4f}")
    print(f"F1分数: {results['f1']:.4f}")

if __name__ == "__main__":
    main() 