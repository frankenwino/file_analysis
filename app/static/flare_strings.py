import subprocess
# import utils

def flare(file_path):

    # print(f"{utils.now()} - flarestrings starting")
    print("flarestrings starting")

    flarestrings = subprocess.Popen(("flarestrings", "-n", "4", file_path), stdout=subprocess.PIPE)
    output = subprocess.check_output(("rank_strings", "-s"), stdin=flarestrings.stdout).decode("utf-8")
    flarestrings.wait()

    # print(f"{utils.now()} - flarestrings complete")
    print("flarestrings complete")

    split_output = output.split("\n")
    output_list = []
    for line in split_output:
        split_line = line.split(",")
        rank = split_line[0].strip()
        the_string = split_line[-1].strip()

        if len(rank) > 0 and len(the_string) > 0:
            rank_dict = {rank: the_string}
            output_list.append(rank_dict)



    return output, output_list


if __name__ == '__main__':
    from pprint import pprint
    file_path = "/home/andy/Desktop/Setup.exe"
    flare_output, flare_output_list = flare(file_path)
    # pprint(flare_output, indent=4)
    # with open("flare.txt", "w") as f:
    #     f.write(flare_output)
    pprint(flare_output_list, indent=4)
    # utils.create_json_file("flare.json", flare_output_list)
