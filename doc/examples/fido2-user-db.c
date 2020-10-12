#include <stdio.h>
#include <sqlite3.h>

int main (void) {
    sqlite3 *db;
    char *err_msg = NULL;

    int rc = sqlite3_open("user.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open/ create database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    char *sql = "CREATE TABLE Users(Ephemeral_username BLOB PRIMARY KEY, Username TEXT, Expiration_time INT);";  
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);

        sqlite3_free(err_msg);
        sqlite3_close(db);

        return 1;
    }
    sqlite3_close(db);
    return 0;
}
