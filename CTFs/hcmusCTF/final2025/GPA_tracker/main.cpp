#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <memory>
#include <csignal>
#include <cctype>

#define NAME_SIZE 51

void enter_safe(char *buf, int32_t size) {
    fgets(buf, size, stdin);
    buf[strcspn(buf, "\n")] = 0;
    for (int32_t i = 0; i < size; i++) {
        if (buf[i] && !isalnum(buf[i]) && !isblank(buf[i])) {
            printf("No no no, no command injection allowed!\n");
            exit(1);
        }
    }
}

bool printable(char *buf) {
    for (char *c = buf; *c; c++) {
        if (!isprint(*c)) return false;
    }
    return true;
}

struct __attribute__((packed)) Student {
    int32_t student_id;
    char name[NAME_SIZE];

    Student() {
    }

    ~Student() {
        if (strlen(name) == 0 || !printable(name)) return;
        char buf[NAME_SIZE + 20] = {0};
        strcat(buf, "echo \"Goodbye ");
        strncat(buf, name, NAME_SIZE);
        strcat(buf, "\"");
        system(buf);
    }
};

struct Course {
    int8_t n_credits;
    float GPA;
    int16_t year_taken;

    Course(int n_credits, int16_t year_taken, float GPA) {
        if (n_credits <= 0 || n_credits > 4) {
            printf("What? No way a course has %d credits\n", n_credits);
            exit(0);
        }
        if (year_taken <= 0 || year_taken > 2025) {
            printf("You took this course in %hd?", year_taken);
            exit(0);
        }
        if (GPA < 0) {
            printf("Bruh.\n");
            exit(0);
        }
        this->n_credits = n_credits;
        this->year_taken = year_taken;
        this->GPA = GPA;
    }
};

void handler(int _) {
    exit(0);
}

__attribute__((constructor)) void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    close(2);
    signal(SIGABRT, handler);
}

int32_t main() {
    Student *st = new Student();
    printf("What's your name? ");
    enter_safe(st->name, NAME_SIZE);
    printf("What's your student id: ");
    scanf("%d", &st->student_id);
    printf("Now I will help you calculate your CPA\n");
    std::vector<std::unique_ptr<Course>> courses;
    char choice[3];
    int idx = 0;
    do {
        int n_credits;
        int16_t year_taken;
        float GPA;
        printf("Course #%d\n", idx++);
        printf("How many credits is this course? > "); 
        scanf("%d", &n_credits);
        printf("What year did you take it? > ");
        scanf("%hd", &year_taken);
        printf("What's your GPA in that course? > ");
        scanf("%f", &GPA);
        courses.push_back(std::make_unique<Course>(n_credits, year_taken, GPA));
        printf("Do you want to add one more course? (y/n) > ");
        scanf("%2s", choice);
    } while (choice[0] == 'y' || choice[0] == 'Y');

    float CPA = 0; 
    int8_t n_credits = 0;
    bool sus = false;
    for (int32_t i = 0; i < courses.size(); i++) {
        if (courses[i]->GPA > 10.0) {
            if (!sus) {
                printf("Wait. Hold up...\n");
                sus = true;
            } else {
                printf("Yeah, I'm sure you've made a mistake.\n");
                exit(0);
            }
        }
        CPA += courses[i]->n_credits * courses[i]->GPA;
        n_credits += courses[i]->n_credits;
    }
    CPA /= n_credits;
    printf("Your CPA is %.2f\n", CPA);
    if (CPA > 10.0) {
        printf("How is that even possible?!\n");
        exit(0);
    }
    if (CPA < 5.0) {
        printf("You seem to love your school ;)\n");
    }
    delete[] st;
    return 0;
}
