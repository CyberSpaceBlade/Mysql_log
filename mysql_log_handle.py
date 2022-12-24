import re
import time
import requests
import xlwt


def log_txt(log_file):
    f = open(log_file, "r")
    text = f.readlines()
    f.close()  # 读取日志文件
    s = r"(\d{4}-\d{2}-\d{2}).*(\d{2}:\d{2}:\d{2}).*@(.*)"
    list = []

    for i in range(0, len(text)):
        temp = re.findall(s, text[i])
        if (temp):  # 根据爆破日志的特点选择特定的表达式，非空是我们要的结果
            if (len(temp[0][2].split("'")) == 3):  # 首条记录不符合要求
                temp1 = temp[0][2].split("'")[1]  # 我们已得到的temp[0]是个元组，且距离我们的目标有差距，所以再处理一下
                temp2 = []
                for i in range(0, len(temp[0]) - 1):
                    temp2.append(temp[0][i])
                temp2.append(temp1)
                list.append(temp2)
    print('恶意IP爆破数据提取完成！')
    return list


def clear(list):
    res = []
    list[0].append(int(1))
    res.append(list[0])
    for i in range(0, len(list) - 1):
        if list[i][2] != list[i + 1][2]:  # ip不同是筛选标准
            list[i + 1].append(int(1))
            res.append(list[i + 1])
        else:
            res[len(res) - 1][3] += 1  # ip相同的会在日志中连续出现

    # 原本我以为这样就可以了，但经过实践发现还是会存在一些特例的情况，例如某些攻击IP不是非常连续，所以进行二次整合
    for i in range(0, len(res)):
        for j in range(i + 1, len(res)):
            if (res[i][2] == res[j][2]):
                res[i][3] += res[j][3]
                res[j][3] = 0  # 去重完成

    f = open("total.txt", "w")  # 将结果写入txt
    for i in range(0, len(res)):
        if (res[i][3] != 0 and res[i][2] != "localhost"):
            f.write(res[i][0] + "\t" + res[i][1] + "\t" + res[i][2] + "\t" + str(res[i][3]) + "\n")
    f.close()
    print("所有恶意IP已写入到本地文件total.txt中！")

    f = open("high_frequency_total.txt", "w")  # 将结果写入txt
    for i in range(0, len(res)):
        if (res[i][3] % 49 != 0 and res[i][3] > 100 and res[i][2] != "localhost"):
            f.write(res[i][0] + "\t" + res[i][1] + "\t" + res[i][2] + "\t" + str(res[i][3]) + "\n")
    f.close()
    print("所有高频ip已写入到high_frequency_total.txt中！")
    print("恶意IP爆破次数统计完毕！")


def locate_excel():
    f = open("high_frequency_total.txt", "r")  # 不选择爬取所有的ip也是出于实际情况，如果对方是代理池中的IP强行爬取没有意义
    text = f.readlines()  # 先获取所有需要用到的IP备用

    excelname = 'mysqld_log.xlsx'
    file_excel = xlwt.Workbook(encoding='utf-8', style_compression=0)
    sheet = file_excel.add_sheet('total_info')  # 新建好一会要用的表格
    col = ('日期', '时间', 'IP', '攻击次数', '国家', '省份', '城市', '区域', 'idc', '运营商', 'net')
    for i in range(0, len(col)):
        sheet.write(0, i, col[i])

    for pos in range(0, len(text)):
        ip_info = text[pos].split("\t")  # 获取已经有的信息并将其转换为列表
        temp = ip_info[2]

        url = "https://ip138.com/iplookup.asp?ip=" + str(temp) + "&action=2"

        headers = {
            "Cookie": '__gads=ID=16b198b8314f1c31-228c77c796d300f7:T=1657369844:RT=1657369844:S=ALNI_MYhWLChERX6lZfLn5rFE_LYyEc-2Q; __gpi=UID=000007851ebd8dc6:T=1657369844:RT=1659143127:S=ALNI_MbH8ggf8w_p7m1ivlqcXaW57eXmHA; __bid_n=18452b881e749e9e3e4207; FEID=v10-85f56633b8595dc1826b5ab13c41b5a8548fbbc5; __xaf_ths__={"data":{"0":1,"1":43200,"2":60},"id":"be2f3e69-cfbf-4a53-b27d-04668e94ab4f"}; __xaf_thstime__=1671845777747; __xaf_fpstarttimer__=1671889710324; FPTOKEN=f02Xmr6MM8WGafoZJ0iSRPJg2DPufUCR0spihtpO66N614LJMuPfpPzC9Z2xM0bf0sVzR234BPsRDgiViCrG8eu3/uiUJuBYc3Ywye01f3i5q257GXOarCbvCtnmLg3m2tYOkrrA40Fb8W2dIIbCG2mSxd5OVuo9pome0iE+/KjwrQjIGRaJdvFxF1qLtnQRO09JF5XuNJbxz+nZr6gbmg+7yniZpUgygZ9779jpYGUle9skA2RexAZ5vBsAHVxmapXg2Z8vHOsYqMszADVxrbHM4Dhpi6Vc9jdIyamjDimhsu5RnEHgCQXJqEFBxVfDHLORI4es90FwX8AFgyVaLsy4srNmLqs3KOg/TZouYr5AxLgl8rHXDTp4lVD/0k4U+PRWQsoAal0QSczT2sk2BQ==|jUFOgfMtjBFiCXUkISrWtfyEkzPz44azXQnSWHuhAvw=|10|7f5226abc338ad5e2c011bd0691ddac0; __xaf_fptokentimer__=1671889710563; Hm_lvt_f4f76646cd877e538aa1fbbdf351c548=1671883398,1671884042,1671889707,1671889876; ASPSESSIONIDCSQQRSCA=PHECIHODJJHGBIIAGEGPMDNP; Hm_lpvt_f4f76646cd877e538aa1fbbdf351c548=1671889893',
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/108.0.0.0 Safari/537.36 "
        }
        answer = requests.get(url, headers=headers)
        code = answer.content.decode("gb18030")

        r1 = r'ip_c_list":(.*)'
        s1 = re.findall(r1, code)
        if (s1):
            s2 = s1[0].split(",")
            for j in range(2, len(s2) - 1):
                s2[j] = s2[j].replace("}]", "")
                s3 = s2[j].split(":")
                ip_info.append(s3[1])

        print("第" + str(pos + 1) + "个高频Ip收集完毕！")
        for k in range(0, len(ip_info)):
            sheet.write(pos + 1, k, ip_info[k])
            print(ip_info[k], end=" ")
            #这两行纯粹是为了先一睹为快看看效果的，也可以等都写入文件了再说，性能上来去不大

        time.sleep(30)  # 为了保证不触发反爬虫机制，建议间隔为一分钟左右。千万不要快速爬，肯定会被发现。
        ip_info.clear()

    file_excel.save(excelname)
    print("恶意IP所在地区信息已搜集完成！保存在本地文件mysqld_log.xlsx中！")


def main():
    #list=log_txt("mysqld.log")
    #clear(list)
    locate_excel()


if __name__ == "__main__":
    main()
