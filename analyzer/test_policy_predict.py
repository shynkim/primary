from policy_predict import predict_texts
if __name__ == "__main__":
    test_text = "카메라와 위치 정보를 수집해서 사용자 맞춤 서비스를 제공합니다. 계정정보는 수집하지 않습니다."
    try:
        result = predict_texts(test_text)
        print("정상 예측 결과:", result)
    except Exception as e:
        import traceback
        print("실행 중 예외 발생:", str(e))
        traceback.print_exc()
