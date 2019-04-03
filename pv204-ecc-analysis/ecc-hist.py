import numpy as np
import matplotlib.pyplot as plt
import os

def convert_ns_to_10ms_and_remove_extremes(filename, output):
    out = open(output, "w")
    with open(filename) as file:
        for line in file:
            if int(line) < 300000:
                row = int(line) // 100
                out.write(str(row) + "\n")

    out.close()

def remove_extremes(filename, output):
    out = open(output, "w")
    with open(filename) as file:
        for line in file:
            if int(line) < 3000:
                out.write(line)

    out.close()

## By Filip Gontko
def convert_file_to_array(filename, sample_size):
    output = []
    counter = 0
    with open(filename, "r") as fp:
        for row in fp:
            if counter == sample_size:
                break
            output.append(int(row))        
    
    return output


## By Filip Gontko
def fill_heat2(first, second, sample_size):
    msb = convert_file_to_array(first, sample_size)
    times = convert_file_to_array(second, sample_size)
    msb_max = max(msb)
    times_max = max(times)

    if times_max >= msb_max:
        maximal = times_max + 1
    else:
        maximal = msb_max + 1

    heat = [[0 for x in range(maximal)] for y in range(maximal)]
    
    for x in range(100000):
        heat[msb[x]][times[x]] += 1
    
    return heat


def heatmap_sign_random():
    data = fill_heat2("randsc_sign_randomdata_msb.txt", "randsc_sign_randomdata_times_100ns.txt", 1000000)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([0, 256])
    plt.xlim([600, 900])
    plt.xlabel("Time to Sign (100ns)")
    plt.ylabel("MSB")
    plt.title('ECDSA Sign Random Data')
    plt.tight_layout()
    f.savefig("randsc_sign_randomdata_msb_heatmap.png")


def heatmap_sign_lhw():
    data = fill_heat2("randsc_sign_lhwdata_msb.txt", "randsc_sign_lhwdata_times_100ns.txt", 1000000)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([0, 256])
    plt.xlim([700, 1000])
    plt.xlabel("Time to Sign (100ns)")
    plt.ylabel("MSB")
    plt.title('ECDSA Sign LHW Data')
    plt.tight_layout()
    f.savefig("randsc_sign_lhwdata_msb_heatmap.png")


def heatmap_sign_hhw():
    data = fill_heat2("randsc_sign_hhwdata_msb.txt", "randsc_sign_hhwdata_times_100ns.txt", 1000000)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([0, 256])
    plt.xlim([700, 1000])
    plt.xlabel("Time to Sign (100ns)")
    plt.ylabel("MSB")
    plt.title('ECDSA Sign HHW Data')
    plt.tight_layout()
    f.savefig("randsc_sign_hhwdata_msb_heatmap.png")

def heatmap_pmul():
    data = fill_heat2("randsc_pmul_msb.txt", "randsc_pmul_times_100ns.txt", 1000000)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([0, 256])
    plt.xlim([1300, 1700])
    plt.xlabel("Time to Multiply (100ns)")
    plt.ylabel("MSB")
    plt.title('ECC Point Multiplication')
    plt.tight_layout()
    f.savefig("randsc_pmul_msb_heatmap.png")

def heatmap_scget():
    data = fill_heat2("randsc_scget_msb.txt", "randsc_scget_times_ex.txt", 1000000)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([0, 256])
    plt.xlim([200, 600])
    plt.xlabel("Time to Retrieve (ns)")
    plt.ylabel("MSB")
    plt.title('Get ECC Scalar')
    plt.tight_layout()
    f.savefig("randsc_scget_msb_heatmap.png")

def heatmap_scclear():
    data = fill_heat2("randsc_scclear_msb.txt", "randsc_scclear_times_ex.txt", 1000000)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([0, 256])
    plt.xlim([200, 600])
    plt.xlabel("Time to Clear (ns)")
    plt.ylabel("MSB")
    plt.title('Clear ECC Scalar')
    plt.tight_layout()
    f.savefig("randsc_scclear_msb_heatmap.png")

def heatmap_scrandom():
    data = fill_heat2("randsc_scrandom_msb.txt", "randsc_scrandom_times_ex.txt", 1000000)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([0, 256])
    plt.xlim([700, 1300])
    plt.xlabel("Time to Generate (ns)")
    plt.ylabel("MSB")
    plt.title('Generate ECC Scalar')
    plt.tight_layout()
    f.savefig("randsc_scrandom_msb_heatmap.png")


def parse_csv_times():
    for filename in os.listdir("."):
        if filename.endswith(".csv"): 
            with open(filename, "r") as fp:
                txt_filename = filename.split(".")[0] + "_times.txt"
                with open(txt_filename, "w") as fp_txt:
                    line = fp.readline()
                    while line:
                        fp_txt.write(line.split(";")[1])
                        line = fp.readline()


def parse_csv_msb():
    for filename in os.listdir("."):
        if filename.endswith(".csv"): 
            with open(filename, "r") as fp:
                txt_filename = filename.split(".")[0] + "_msb.txt"
                with open(txt_filename, "w") as fp_txt:
                    line = fp.readline()
                    while line:
                        scalar = line.split(";")[0]
                        scalar_bytes = bytes.fromhex(scalar)
                        msb = scalar_bytes[0]
                        fp_txt.write(str(msb) + "\n")
                        line = fp.readline()


def parse_csv_lsb():
    for filename in os.listdir("."):
        if filename.endswith(".csv"): 
            with open(filename, "r") as fp:
                txt_filename = filename.split(".")[0] + "_lsb.txt"
                with open(txt_filename, "w") as fp_txt:
                    line = fp.readline()
                    while line:
                        scalar = line.split(";")[0]
                        scalar_bytes = bytes.fromhex(scalar)
                        msb = scalar_bytes[len(scalar_bytes) - 1]
                        fp_txt.write(str(msb) + "\n")
                        line = fp.readline()


def scalar_get():
    f1 = np.loadtxt('randsc_scget_times.txt', unpack='False')
    f2 = np.loadtxt('lhwsc_scget_times.txt', unpack='False')
    f3 = np.loadtxt('hhwsc_scget_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=90, label="Random Scalar", alpha=0.6, range=(300, 390))
    plt.hist(f2, histtype='bar',color="red", bins=90, label="LHW Scalar", alpha=0.6, range=(300, 390))
    plt.hist(f3, histtype='bar',color="green", bins=90, label="HHW Scalar", alpha=0.6, range=(300, 390))
    plt.xlabel('Time to retrieve (ns)')
    plt.ylabel('Frequency')
    plt.title('Get ECC Scalar')
    plt.legend()
    plt.tight_layout()
    plt.savefig("scget.png")
    plt.cla()

def scalar_random():
    f1 = np.loadtxt('randsc_scrandom_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=115, alpha=1, range=(745, 860))
    plt.xlabel('Time to generate (ns)')
    plt.ylabel('Frequency')
    plt.title('Generate ECC Scalar')
    plt.savefig("scrandom.png")
    plt.cla()

def scalar_clear():
    f1 = np.loadtxt('randsc_scclear_times.txt', unpack='False')
    f2 = np.loadtxt('lhwsc_scclear_times.txt', unpack='False')
    f3 = np.loadtxt('hhwsc_scclear_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=55, label="Random Scalar", alpha=0.6, range=(305, 360))
    plt.hist(f2, histtype='bar',color="red", bins=55, label="LHW Scalar", alpha=0.6, range=(305, 360))
    plt.hist(f3, histtype='bar',color="green", bins=55, label="HHW Scalar", alpha=0.6, range=(305, 360))
    plt.xlabel('Time to clear (ns)')
    plt.ylabel('Frequency')
    plt.title('Clear ECC Scalar')
    plt.legend()
    plt.tight_layout()
    plt.savefig("scclear.png")
    plt.cla()

def sign_random():
    f1 = np.loadtxt('randsc_sign_randomdata_times.txt', unpack='False')
    f2 = np.loadtxt('lhwsc_sign_randomdata_times.txt', unpack='False')
    f3 = np.loadtxt('hhwsc_sign_randomdata_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=200, label="Random Scalar", alpha=0.6, range=(72500, 86000))
    plt.hist(f2, histtype='bar',color="red", bins=200, label="LHW Scalar", alpha=0.6, range=(72500, 86000))
    plt.hist(f3, histtype='bar',color="green", bins=200, label="HHW Scalar", alpha=0.6, range=(72500, 86000))
    plt.xlabel('Time to sign (ns)')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign Random Data')
    plt.legend()
    plt.tight_layout()
    plt.savefig("sign_random.png")
    plt.cla()

def sign_lhw():
    f1 = np.loadtxt('randsc_sign_lhwdata_times.txt', unpack='False')
    f2 = np.loadtxt('lhwsc_sign_lhwdata_times.txt', unpack='False')
    f3 = np.loadtxt('hhwsc_sign_lhwdata_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=200, label="Random Scalar", alpha=0.6, range=(79000, 88000))
    plt.hist(f2, histtype='bar',color="red", bins=200, label="LHW Scalar", alpha=0.6, range=(79000, 88000))
    plt.hist(f3, histtype='bar',color="green", bins=200, label="HHW Scalar", alpha=0.6, range=(79000, 88000))
    plt.xlabel('Time to sign (ns)')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign LHW Data')
    plt.legend()
    plt.tight_layout()
    plt.savefig("sign_lhw.png")
    plt.cla()

def sign_hhw():
    f1 = np.loadtxt('randsc_sign_hhwdata_times.txt', unpack='False')
    f2 = np.loadtxt('lhwsc_sign_hhwdata_times.txt', unpack='False')
    f3 = np.loadtxt('hhwsc_sign_hhwdata_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=200, label="Random Scalar", alpha=0.6, range=(76500, 89000))
    plt.hist(f2, histtype='bar',color="red", bins=200, label="LHW Scalar", alpha=0.6, range=(76500, 89000))
    plt.hist(f3, histtype='bar',color="green", bins=200, label="HHW Scalar", alpha=0.6, range=(76500, 89000))
    plt.xlabel('Time to sign (ns)')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign HHW Data')
    plt.legend()
    plt.tight_layout()
    plt.savefig("sign_hhw.png")
    plt.cla()

def point_mul():
    f1 = np.loadtxt('randsc_pmul_times.txt', unpack='False')
    f2 = np.loadtxt('lhwsc_pmul_times.txt', unpack='False')
    f3 = np.loadtxt('hhwsc_pmul_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=200, label="Random Scalar", alpha=0.6, range=(141500, 167500))
    plt.hist(f2, histtype='bar',color="red", bins=200, label="LHW Scalar", alpha=0.6, range=(141500, 167500))
    plt.hist(f3, histtype='bar',color="green", bins=200, label="HHW Scalar", alpha=0.6, range=(141500, 167500))
    plt.xlabel('Time to multiply (ns)')
    plt.ylabel('Frequency')
    plt.title('ECC Point Multiplication')
    plt.legend()
    plt.tight_layout()
    plt.savefig("pmul.png")
    plt.cla()

def lhwhhw_k():
    f1 = np.loadtxt('randsc_sign_randomdata_lhw_times.txt', unpack='False')
    f2 = np.loadtxt('randsc_sign_randomdata_hhw_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=200, label="LHW nonce", alpha=0.6, range=(80000, 95000))
    plt.hist(f2, histtype='bar',color="red", bins=200, label="HHW nonce", alpha=0.6, range=(80000, 95000))
    plt.xlabel('Time to Sign (ns)')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign Random Data Random Scalar')
    plt.legend()
    plt.tight_layout()
    plt.savefig("random_sign_nonce.png")
    plt.cla()

def lhwhhw_k_lhw():
    f1 = np.loadtxt('lhwsc_sign_randomdata_lhw_times.txt', unpack='False')
    f2 = np.loadtxt('lhwsc_sign_randomdata_hhw_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=200, label="LHW nonce", alpha=0.6, range=(76000, 86000))
    plt.hist(f2, histtype='bar',color="red", bins=200, label="HHW nonce", alpha=0.6, range=(76000, 86000))
    plt.xlabel('Time to Sign (ns)')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign Random Data LHW Scalar')
    plt.legend()
    plt.tight_layout()
    plt.savefig("lhw_sign_nonce.png")
    plt.cla()

def lhwhhw_k_hhw():
    f1 = np.loadtxt('hhwsc_sign_randomdata_lhw_times.txt', unpack='False')
    f2 = np.loadtxt('hhwsc_sign_randomdata_hhw_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=200, label="LHW nonce", alpha=0.6, range=(68000, 85000))
    plt.hist(f2, histtype='bar',color="red", bins=200, label="HHW nonce", alpha=0.6, range=(68000, 85000))
    plt.xlabel('Time to Sign (ns)')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign Random Data HHW Scalar')
    plt.legend()
    plt.tight_layout()
    plt.savefig("hhw_sign_nonce.png")
    plt.cla()

def point_mul_zoom():
    f1 = np.loadtxt('randsc_pmul_times.txt', unpack='False')
    f2 = np.loadtxt('lhwsc_pmul_times.txt', unpack='False')
    f3 = np.loadtxt('hhwsc_pmul_times.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=100, label="Random Scalar", alpha=0.6, range=(152500, 154500))
    plt.hist(f2, histtype='bar',color="red", bins=100, label="LHW Scalar", alpha=0.6, range=(152500, 154500))
    plt.hist(f3, histtype='bar',color="green", bins=100, label="HHW Scalar", alpha=0.6, range=(152500, 154500))
    plt.xlabel('Time to multiply (ns)')
    plt.ylabel('Frequency')
    plt.title('ECC Point Multiplication')
    plt.legend()
    plt.tight_layout()
    plt.savefig("pmul_zoom2.png")
    plt.cla()

def msb_hist():
    f1 = np.loadtxt('randsc_pmul_msb.txt', unpack='False')
    f2 = np.loadtxt('randsc_scget_msb.txt', unpack='False')
    f3 = np.loadtxt('randsc_scclear_msb.txt', unpack='False')
    f4 = np.loadtxt('randsc_scrandom_msb.txt', unpack='False')
    f5 = np.loadtxt('randsc_sign_lhwdata_msb.txt', unpack='False')
    f6 = np.loadtxt('randsc_sign_hhwdata_msb.txt', unpack='False')
    f7 = np.loadtxt('randsc_sign_randomdata_msb.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('MSB')
    plt.ylabel('Frequency')
    plt.title('ECC Point Multiplication')
    plt.tight_layout()
    plt.savefig("pmul_msb.png")
    plt.cla()

    plt.hist(f2, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('MSB')
    plt.ylabel('Frequency')
    plt.title('Get ECC Scalar')
    plt.tight_layout()
    plt.savefig("scget_msb.png")
    plt.cla()

    plt.hist(f3, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('MSB')
    plt.ylabel('Frequency')
    plt.title('Clear ECC Scalar')
    plt.tight_layout()
    plt.savefig("scclear_msb.png")
    plt.cla()

    plt.hist(f4, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('MSB')
    plt.ylabel('Frequency')
    plt.title('Generate ECC Scalar')
    plt.tight_layout()
    plt.savefig("scrandom_msb.png")
    plt.cla()

    plt.hist(f5, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('MSB')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign LHW Data')
    plt.tight_layout()
    plt.savefig("sign_lhw_msb.png")
    plt.cla()

    plt.hist(f6, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('MSB')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign HHW Data')
    plt.tight_layout()
    plt.savefig("sign_hhw_msb.png")
    plt.cla()

    plt.hist(f7, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('MSB')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign Random Data')
    plt.tight_layout()
    plt.savefig("sign_random_msb.png")
    plt.cla()


def lsb_hist():
    f1 = np.loadtxt('randsc_pmul_lsb.txt', unpack='False')
    f2 = np.loadtxt('randsc_scget_lsb.txt', unpack='False')
    f3 = np.loadtxt('randsc_scclear_lsb.txt', unpack='False')
    f4 = np.loadtxt('randsc_scrandom_lsb.txt', unpack='False')
    f5 = np.loadtxt('randsc_sign_lhwdata_lsb.txt', unpack='False')
    f6 = np.loadtxt('randsc_sign_hhwdata_lsb.txt', unpack='False')
    f7 = np.loadtxt('randsc_sign_randomdata_lsb.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('LSB')
    plt.ylabel('Frequency')
    plt.title('ECC Point Multiplication')
    plt.tight_layout()
    plt.savefig("pmul_lsb.png")
    plt.cla()

    plt.hist(f2, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('LSB')
    plt.ylabel('Frequency')
    plt.title('Get ECC Scalar')
    plt.tight_layout()
    plt.savefig("scget_lsb.png")
    plt.cla()

    plt.hist(f3, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('LSB')
    plt.ylabel('Frequency')
    plt.title('Clear ECC Scalar')
    plt.tight_layout()
    plt.savefig("scclear_lsb.png")
    plt.cla()

    plt.hist(f4, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('LSB')
    plt.ylabel('Frequency')
    plt.title('Generate ECC Scalar')
    plt.tight_layout()
    plt.savefig("scrandom_lsb.png")
    plt.cla()

    plt.hist(f5, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('LSB')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign LHW Data')
    plt.tight_layout()
    plt.savefig("sign_lhw_lsb.png")
    plt.cla()

    plt.hist(f6, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('LSB')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign HHW Data')
    plt.tight_layout()
    plt.savefig("sign_hhw_lsb.png")
    plt.cla()

    plt.hist(f7, histtype='bar',color="blue", bins=256, alpha=1, range=(0, 256))
    plt.xlabel('LSB')
    plt.ylabel('Frequency')
    plt.title('ECDSA Sign Random Data')
    plt.tight_layout()
    plt.savefig("sign_random_lsb.png")
    plt.cla()


def findmaxmin(filename):
    with open(filename, "r") as fp:
        max_val = 0
        min_val = 1000000000
        counter = 0
        line = fp.readline()
        while line:
            if int(line) < min_val:
                min_val = int(line)
            if int(line) > max_val:
                max_val = int(line)
            if int(line) > 250000:
                counter += 1
            line = fp.readline()
        print(str(max_val))
        print(str(min_val))
        print(str(counter))

if __name__ == "__main__":
    
    parse_csv_times()
    #scalar_get()
    #scalar_random()
    #scalar_clear()
    #sign_random()
    #sign_hhw()
    #sign_lhw()
    #point_mul()
    #point_mul_zoom()
    #parse_csv_msb()
    #msb_hist()
    #parse_csv_lsb()
    #lsb_hist()
    #remove_extremes("randsc_scclear_times.txt", "randsc_scclear_times_ex.txt")
    #remove_extremes("randsc_scget_times.txt", "randsc_scget_times_ex.txt")
    #remove_extremes("randsc_scrandom_times.txt", "randsc_scrandom_times_ex.txt")
    #heatmap_scclear()
    #heatmap_scget()
    #heatmap_scrandom()
    lhwhhw_k()
    lhwhhw_k_hhw()
    lhwhhw_k_lhw()