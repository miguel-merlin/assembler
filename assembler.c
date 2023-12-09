/*
    name: Miguel Merlin, Alice Agnoletto
    pledge: "I pledge my honor that I have abided by the Stevens Honor System."
*/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/*

To compile:
gcc -o assembler assembler.c
To run:
./assembler <filenames>
Example:
./assembler test.txt

*/

char *valid_mnemonics[] = {"add", "mul", "ldr", "str", "mov", "adr"};
char *valid_directives[] = {".byte", ".int", ".word", ".quad", ".dword", ".single", ".float", ".double", ".string", ".ascii"};
int directive_sizes[] = {1, 4, 2, 8, 4, 4, 4, 8, 1, 1};
int line_size = 17;
char *current_address = "0000";

bool validate_files(int argc, char *argv[]) {
    if (argc == 1) {
        printf("Usage: ./assembler <filenames>\n");
        return false;
    }

    for (int i = 1; i < argc; i++) {
        char *filename = argv[i];
        int file_len = strlen(filename);

        // Check that all files end in .txt
        if (file_len > 4 && strcmp(filename + file_len - 4, ".txt") != 0) {
            printf("Error: %s is not a .txt file\n", filename);
            return false;
        }
    }
    return true;
}

FILE* open_file(char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Error: %s does not exist\n", filename);
        return NULL;
    }
    return fp;
}

bool validate_mnemonic(char *mnemonic) {
    // Check if mnemonic is null
    if (mnemonic == NULL) {
        printf("Error: %s is not a valid mnemonic\n", mnemonic);
        return false;
    }

    // Convert mnemonic to lowercase
    for (int i = 0; mnemonic[i]; i++) {
        mnemonic[i] = tolower(mnemonic[i]);
    }

    // Check if mnemonic is valid
    bool valid = false;
    for (int i = 0; i < 6; i++) {
        if (strcmp(mnemonic, valid_mnemonics[i]) == 0) {
            valid = true;
            break;
        }
    }

    return valid;
}

char *trim_space(char *str) {
    if (str == NULL) {
        return NULL;
    }

    char *end;

    // Trim leading space
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0)  return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator character
    end[1] = '\0';

    return str;
}

bool validate_register(char *reg) {
    // Trim leading and trailing spaces
    reg = trim_space(reg);  

    // Check if register is null
    if (reg == NULL) {
        printf("Error: %s is not a valid register\n", reg);
        return false;
    }

    // Check if register is r0-r3
    if (strlen(reg) == 2 && (reg[0] == 'x' || reg[0] == 'X') && reg[1] >= '0' && reg[1] <= '3') {
        return true;
    }

    return false;
}

bool check_immediate(char* offset) {
    if (offset == NULL) {
        return false;
    }

    trim_space(offset);

    // Check if immediate is a number
    for (int i = 0; i < strlen(offset); i++) {
        if (offset[i] == ' ' || offset[i] == '\t' || offset[i] == '#') {
            continue;
        }
        if (!isdigit(offset[i])) {
            return false;
        }
    }

    return true;
}

char* convert_str_to_binary(char* number) {
    int num = atoi(number);
    char* binary = (char*) malloc(5);
    binary[4] = '\0';
    for (int i = 3; i >= 0; --i, num >>= 1)
        binary[i] = (num & 1) + '0';
    return binary;
}

char* create_binary_string(char* line, bool to, bool write_reg, bool immediate_control, bool read_mem, bool write_mem, char* rd, char* rn, char* rm) {
    if (line == NULL) {
        return NULL;
    }

    rd = trim_space(rd);
    char rd_char[2] = {rd[1], '\0'};
    rd = convert_str_to_binary(rd_char);

    rn = trim_space(rn);
    char rn_char[2] = {rn[1], '\0'};
    rn = convert_str_to_binary(rn_char);

    if (immediate_control) {
        rm = trim_space(rm);
        rm = convert_str_to_binary(rm);
    } else {
        rm = trim_space(rm);
        char rm_char[2] = {rm[1], '\0'};
        rm = convert_str_to_binary(rm_char);
    }
    
    // Create binary string
    strcat(line, to ? "1" : "0");
    strcat(line, write_reg ? "1" : "0");
    strcat(line, immediate_control ? "1" : "0");
    strcat(line, read_mem ? "1" : "0");
    strcat(line, write_mem ? "1" : "0");

    strcat(line, rm);
    strcat(line, rn);
    strcat(line, rd);

    // Null terminate string
    line[line_size - 1] = '\0';

    return line;
}

char* encode_instruction(char *instruction, char **label_names, int *label_size) {
    bool to;
    bool write_reg;
    bool immediate_control;
    bool read_mem;
    bool write_mem;

    char* mnemonic = strtok(instruction, " ");
    char* rd;
    char* rn;
    char* rm;

    // Check if mnemonic is valid
    if (mnemonic == NULL) {
        printf("Error: %s is not a valid mnemonic\n", mnemonic);
        return NULL;
    }

    if (!validate_mnemonic(mnemonic)) {
        printf("Error: %s is not a valid mnemonic\n", mnemonic);
        return NULL;
    }

    // Check if Rd is valid
    rd = strtok(NULL, ",");
    if (!validate_register(rd)) {
        printf("Error: %s is not a valid register\n", rd);
        return NULL;
    }

    // Check if instruction access memory
    if (strcmp(mnemonic, "ldr") == 0 || strcmp(mnemonic, "str") == 0) {
        char *adr_and_offset = strtok(NULL, "");
        adr_and_offset = strchr(adr_and_offset, '[');

        rn = strtok(adr_and_offset, "[, ]");
        if (!validate_register(rn)) {
            printf("Error: %s is not a valid register\n", rn);
            return NULL;
        }

        char *offset = strtok(NULL, "[, ]");

        // Check if offset is immediate
        immediate_control = check_immediate(offset);
        if (!immediate_control && !validate_register(offset)) {
            printf("Error: %s is not a valid register\n", offset);
            return NULL;
        }
        rm = offset;

    } else {
        if (strcmp(mnemonic, "mov") == 0) {
            rn = rd;
        } else if (strpcmp(mnemonic, "adr") == 0) {
            // Check if label is in label_names
            char* label = strtok(NULL, ",");
            trim_space(label);
            int index = -1;
            for (int i = 0; i < 20; i++) {
                if (strcmp(label, label_names[i]) == 0) {
                    index = i;
                    break;
                }
            }
            if (index == -1) {
                printf("Error: %s is not a valid label\n", label);
                return NULL;
            }
            char* initial_address = "0000";

            // Update initial address with size until i
            for (int i = 0; i < index; i++) {
                int size = label_size[i];
                int value = strtol(initial_address, NULL, 16); // Convert the initial address from hex to int
                value += size;
                sprintf(initial_address, "%04x", value); // Convert the updated value back to hex
            }
            rn = initial_address;
        } else {
            rn = strtok(NULL, ",");
            if (!validate_register(rn)) {
                printf("Error: %s is not a valid register\n", rn);
                return NULL;
            }
        }
        rm = strtok(NULL, "");
        trim_space(rm);
        immediate_control = check_immediate(rm);
    }
    if (strcmp(mnemonic, "str") == 0) {
        write_mem = 1;
        write_reg = 0;
    } else {
        write_mem = 0;
        write_reg = 1;
    }

    if (strcmp(mnemonic, "ldr") == 0) {
        read_mem = 1;
    } else {
        read_mem = 0;
    }

    if (strcmp(mnemonic, "mul") == 0) {
        to = 1;
    } else {
        to = 0;
    }

    char* line = (char*) malloc(line_size * sizeof(char));
    line[0] = '\0';
    create_binary_string(line, to, write_reg, immediate_control, read_mem, write_mem, rd, rn, rm);
    
    // Create binary string
    return line;
}

char* binary_to_hex(char* binary) {
    char* hex = (char*) malloc(5 * sizeof(char));
    int value = 0;
    for (int i = 0; i < 16; i++) {
        value *= 2;
        if (binary[i] == '1') {
            value += 1;
        }
    }
    sprintf(hex, "%01X", value);
    return hex;
}

void convert_instruction_to_hex(char* instruction, FILE *output_file) {
    if (instruction == NULL) {
        return;
    }
    if (strlen(instruction) != 16) {
        printf("Error: %s is not a valid instruction\n", instruction);
        return;
    }

    char* hex = binary_to_hex(instruction);

    fprintf(output_file, "%s\n", hex);

    free(hex);
}

bool handle_text_segment(char *line, FILE *input_file, FILE *output_file, char **label_names, int *label_size) {
    while (fgets(line, 256, input_file) != NULL) {
        char* pos;
        if ((pos=strchr(line, '\n')) != NULL) *pos = '\0';

        if (strcmp(line, "\n") == 0 || strcmp(line, "") == 0) {
            continue;
        }

        if (strcmp(line, ".data") == 0) {
            break;
        }
        char* encoded_instruction = encode_instruction(line, label_names, label_size);
        if (encoded_instruction == NULL) {
            return false;
        }
        convert_instruction_to_hex(encoded_instruction, output_file);
        free(encoded_instruction);
    }
    return true;
}

int get_directive_size(char* directive) {
    if (directive == NULL || directive[0] != '.') {
        return -1;
    }

    // Check if directive is in valid_directives
    for (int i = 0; i < 10; i++) {
        if (strcmp(directive, valid_directives[i]) == 0) {
            return i;
        }
    }
    return -1;
}

bool convert_data_to_hex(char* data, int size, FILE *output_file) {
    if (data == NULL) {
        return false;
    }
    // Allocate a buffer to hold the hexadecimal representation of the data
    char* hex = malloc(size * 2 + 1);
    if (hex == NULL) {
        return false;
    }

    // Convert the data to hexadecimal
    for (int i = 0; i < size; i++) {
        sprintf(hex + i * 2, "%02x", (unsigned char)data[i]);
    }

    // Write the hexadecimal data to the output file
    fprintf(output_file, "%s", hex);

    // Free the buffer
    free(hex);
    return true;
}

bool convert_data(char* line, int size_data, FILE *output_file, int *label_size, int label_count) {
    int size = 0;
    while (strtok(NULL, ",") != NULL) {
        size += directive_sizes[size_data];
        if (!convert_data_to_hex(line, size, output_file)) {
            return false;
        }
    }

    // Update label_size
    label_size[label_count] = size;

    // Update current_address
    int value = strtol(current_address, NULL, 16); // Convert the initial address from hex to int
    value += size;
    sprintf(current_address, "%04x", value); // Convert the updated value back to hex

    return true;
} 

bool encode_data(char* data, FILE *output_file, char **label_names, int *label_size, int label_count) {
    if (data == NULL) {
        return false;
    }
    trim_space(data);
    char* label = strtok(data, " ");
    char* directive = strtok(NULL, " ");
    int size = get_directive_size(directive); // i in directive_sizes
    if (size == -1) {
        printf("Error: %s is not a valid directive\n", directive);
        return false;
    }
    if (!convert_data(data, size, output_file, label_size, label_count)) {
        return false;
    }
    label_names[label_count] = label;
    return true;
}

bool handle_data_segment(char *line, FILE *input_file, FILE *output_file, char **label_names, int *label_size) {
    int label_count = 0;
    while (fgets(line, 256, input_file) != NULL) {
        char* pos;
        if ((pos=strchr(line, '\n')) != NULL) *pos = '\0';

        if (strcmp(line, ".text") == 0) {
            printf("Error: .text segment must come before .data segment\n");
            return false;
        }
        if (!encode_data(line, output_file, label_names, label_size, label_count)) {
            return false;
        }
        label_count++;
    }
    return true;
}

char* encode(char *filename, FILE *output_file, FILE *data_file, char **label_names, int *label_size) {
    FILE *fp = open_file(filename);

    // Check if file was opened successfully
    if (fp == NULL) {
        return NULL;
    }

    // Encode each line
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char* pos;
        if ((pos=strchr(line, '\n')) != NULL) *pos = '\0';

        if (strncmp(line, ".text", 5) == 0) {
            if (!handle_text_segment(line, fp, output_file, label_names, label_size)) {
                return NULL;
            }
        }
        if (strcmp(line, ".data") == 0) {
            if (!handle_data_segment(line, fp, data_file, label_names, label_size)) {
                return NULL;
            }
        }
    }

    fclose(fp);
    return filename;
}

int main(int argc, char *argv[]) {
    // Validate file names
    if (!validate_files(argc, argv)) {
        return 1;
    }

    // Create instructions.txt file
    FILE *output_file = fopen("instructions.txt", "w");
    if (output_file == NULL) {
        printf("Error: instructions.txt could not be created\n");
        return 1;
    }

    // Create data.txt file
    FILE *data_file = fopen("data.txt", "w");
    if (data_file == NULL) {
        printf("Error: data.txt could not be created\n");
        return 1;
    }

    // Write header in file
    fprintf(output_file, "v2.0 raw\n");

    // Write header in data file
    fprintf(data_file, "v2.0 raw\n");

    char **label_names = malloc(20 * sizeof(char *));
    for (int i = 0; i < 20; i++) {
        label_names[i] = malloc(20 * sizeof(char));
    }

    int *label_size = malloc(20 * sizeof(int));
    for (int i = 0; i < 20; i++) {
        label_size[i] = 0;
    }

    // Encode each file
    for (int i = 1; i < argc; i++) {
        char *filename = argv[i];
        char *encoded_filename = encode(filename, output_file, data_file, label_names, label_size);
        
        if (encoded_filename == NULL) {
            return 1;
        }
    }

    fclose(output_file);

    printf("Success!\n");
    printf("You can find the image with enconded instructions in instructions.txt\n");
    printf("You can find the image with enconded data in data.txt\n");
    
    return 0;
}