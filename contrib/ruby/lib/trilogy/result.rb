class Trilogy
  class Result
    attr_reader :fields, :rows, :query_time, :affected_rows, :last_insert_id

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

    def columns
      @columns ||= _columns
    end

    include Enumerable

    class Column
      attr_reader :name, :type, :length, :flags, :charset, :decimals

      def initialize(name, type, length, flags, charset, decimals)
        @name, @type, @length, @flags, @charset, @decimals = name, type, length, flags, charset, decimals
      end
    end
  end
end
