class T:
    result = []

def demo():
    for i in range(0,20):
        T.result.append({"filename": i, "entropy": round(i, 2),
                                "latestTime": i})
    return T
if __name__ == '__main__':

    demo()
    print(T.result)
