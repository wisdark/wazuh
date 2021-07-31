/**
 * @file fim_db_files.h
 * @brief Definition of FIM database for files library.
 * @date 2020-09-9
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef FIM_DB_FILES_H
#define FIM_DB_FILES_H

#include "fim_db.h"

/**
 * @brief Get list of all paths by storing them in a temporal file.
 *
 * @param fim_sql FIM database struct.
 * @param index Type of query.
 * @param fd File where all paths will be stored.
 *
 * @return FIM entry struct on success, NULL on error.
 */
int fim_db_get_multiple_path(fdb_t *fim_sql, int index, FILE *fd);

/**
 * @brief Get entry data using path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 *
 * @return FIM entry struct on success, NULL on error.
 */
fim_entry *fim_db_get_path(fdb_t *fim_sql, const char *file_path);

/**
 * @brief Get all the paths asociated to an inode
 *
 * @param fim_sql FIM databse struct.
 * @param inode Inode.
 * @param dev Device.
 *
 * @return char** An array of the paths asociated to the inode.
 */
char **fim_db_get_paths_from_inode(fdb_t *fim_sql, unsigned long int inode, unsigned long int dev);

/**
 * @brief Get all the paths asociated to an inode
 *
 * @param fim_sql FIM databse struct.
 * @param inode Inode.
 * @param dev Device.
 * @param list A list to which the paths retrieved from the DB will be added to.
 * @param tree A tree which helps avoid the operation from appending paths that already exist in the list.
 *
 * @return The number of paths retrieved from the DB
 */
int fim_db_append_paths_from_inode(fdb_t *fim_sql,
                                   unsigned long int inode,
                                   unsigned long int dev,
                                   OSList *list,
                                   rb_tree *tree);

/**
 * @brief Insert or update entry data.
 *
 * @param fim_sql FIM database struct.
 * @param entry Entry data to be inserted.
 * @param row_id Row id to insert data.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_data(fdb_t *fim_sql, const fim_file_data *entry, int *row_id);

/**
 * @brief Insert or update entry path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param entry Entry data to be inserted.
 * @param inode_id Inode id to insert.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, const fim_file_data *entry, int inode_id);

/**
 * @brief Insert an entry in the needed tables.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param new Entry data to be inserted.
 * @param saved Entry with existing data.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert(fdb_t *fim_sql, const char *file_path, const fim_file_data *new, const fim_file_data *saved);

/**
 * @brief Delete entry from the DB using file path.
 *
 * @param fim_sql FIM database struct.
 * @param path Path of the entry to be removed.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_path(fdb_t *fim_sql, const char *path);

/**
 * @brief Set all entries from database to unscanned.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_unscanned(fdb_t *fim_sql);

/**
 * @brief Set file entry scanned.
 *
 * @param fim_sql FIM database struct.
 * @param path File path.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_scanned(fdb_t *fim_sql, const char *path);

/**
 * @brief Get all the unscanned files by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage);

/**
 * @brief Delete not scanned entries from database.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_not_scanned(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage);

/**
 * @brief Removes a range of paths from the database.
 *
 * The paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param evt_data Information on how the event was triggered.
 * @param configuration An integer holding the position of the configuration that corresponds to the entries to be deleted.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_range(fdb_t *fim_sql,
                        fim_tmp_file *file,
                        pthread_mutex_t *mutex,
                        int storage,
                        event_data_t *evt_data,
                        directory_t *configuration);

/**
 * @brief Remove a range of paths from database if they have a specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param evt_data Information on how the event was triggered.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_entry(fdb_t *fim_sql,
                                 fim_tmp_file *file,
                                 pthread_mutex_t *mutex,
                                 int storage,
                                 event_data_t *evt_data);

/**
 * @brief Remove a wildcard directory that were not expanded from the configuration
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param evt_data Information on how the event was triggered.
 * @param configuration An integer holding the position of the configuration that corresponds to the entries to be deleted.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_wildcard_entry(fdb_t *fim_sql,
                                 fim_tmp_file *file,
                                 pthread_mutex_t *mutex,
                                 int storage,
                                 event_data_t *evt_data,
                                 directory_t *configuration);

/**
 * @brief Decodes a row from the database to be saved in a fim_entry structure.
 *
 * @param stmt The statement to be decoded.
 *
 * @return fim_entry* The filled structure.
 */
fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt);

/**
 * @brief Get count of all entries in file_data table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in file_data table.
 */
int fim_db_get_count_file_data(fdb_t * fim_sql);

/**
 * @brief Get count of all entries in file_entry table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in file_entry table.
 */
int fim_db_get_count_file_entry(fdb_t * fim_sql);

/**
 * @brief Get path list using the sqlite LIKE operator using @pattern. (stored in @file).
 * @param fim_sql FIM database struct.
 * @param pattern Pattern that will be used for the LIKE operation.
 * @param file Structure of the storage which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_path_from_pattern(fdb_t *fim_sql, const char *pattern, fim_tmp_file **file, int storage);

/**
 * @brief Verifies if the data row identified by a given device and inode exists in file_data.
 *
 * @param fim_sql FIM database struct.
 * @param inode The inode to look for.
 * @param dev The device that must be associated with the desired inode.
 *
 * @return An integer signaling wheter the row exists or not.
 * @retval 1 if the row exists.
 * @retval 0 if the row does not exist.
 * @retval FIMDB_ERR if an error occurs when executing the query.
 */
int fim_db_data_exists(fdb_t *fim_sql, unsigned long int inode, unsigned long int dev);

/**
 * @brief Checks the DB to see if a given file has already been scanned.
 *
 * @param fim_sql FIM database struct.
 * @param path Path to the file we want to verify.
 * @return An integer signaling if the files was scanned or not.
 * @retval 1 if the files was scanned already.
 * @retval 0 if tha file has not been scanned or no entry was found on the DB.
 * @retval FIMDB_ERR if an error happened during the query.
 */
int fim_db_file_is_scanned(fdb_t *fim_sql, const char *path);

#endif /* FIM_DB_FILES_H */
