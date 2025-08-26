import numpy as np

def calculate_average(data_list):
    """
    Calculates the average of a list of numbers using numpy.
    """
    if not isinstance(data_list, list) or not data_list:
        print("Error: Input must be a non-empty list.")
        return None

    # Use numpy's mean function
    avg = np.mean(data_list)
    print(f"The average of the list is: {avg}")
    return avg

if __name__ == "__main__":
    my_data = [10, 20, 30, 40, 50]
    calculate_average(my_data)
