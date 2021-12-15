require "trilogy/cext"
require "trilogy/version"

class Trilogy
  def in_transaction?
    (server_status & SERVER_STATUS_IN_TRANS) != 0
  end

  def server_info
    version_str = server_version

    if /\A(\d+)\.(\d+)\.(\d+)/ =~ version_str
      version_num = ($1.to_i * 10000) + ($2.to_i * 100) + $3.to_i
    end

    { :version => version_str, :id => version_num }
  end

  def connected_host
    @connected_host ||= query_with_flags("select @@hostname", query_flags | QUERY_FLAGS_FLATTEN_ROWS).rows.first
  end

  def query_with_flags(sql, flags)
    old_flags = query_flags
    self.query_flags = flags

    query(sql)
  ensure
    self.query_flags = old_flags
  end
end

Trilogy::Result.class_eval do
  def count
    rows.count
  end

  def each_hash
    return enum_for(:each_hash) unless block_given?

    rows.each do |row|
      this_row = {}

      idx = 0
      row.each do |col|
        this_row[fields[idx]] = col
        idx += 1
      end

      yield this_row
    end

    self
  end

  def each(&bk)
    rows.each(&bk)
  end

  include Enumerable
end
